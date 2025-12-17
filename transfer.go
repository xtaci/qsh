package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/xtaci/qsh/protocol"
)

// uploadFile streams a local file to the remote server over an authenticated client session.
func (s *clientSession) uploadFile(localPath, remotePath string) error {
	info, err := os.Stat(localPath)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", localPath)
	}
	perm := uint32(info.Mode().Perm())

	// send upload request
	req := &protocol.FileTransferRequest{
		Direction: protocol.FileDirection_FILE_DIRECTION_UPLOAD,
		Path:      remotePath,
		Size:      uint64(info.Size()),
		Perm:      perm,
	}
	if err := s.Channel.Send(&protocol.PlainPayload{FileRequest: req}); err != nil {
		return err
	}

	// await server readiness
	ready, err := s.awaitFileResult()
	if err != nil {
		return err
	}
	if !ready.Success {
		return errors.New(ready.Message)
	}

	// stream file contents
	file, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer file.Close()
	buf := make([]byte, fileCopyBufferSize)
	var offset uint64
	for {
		n, readErr := file.Read(buf)
		if n > 0 {
			chunk := &protocol.FileTransferChunk{Data: append([]byte(nil), buf[:n]...), Offset: offset}
			offset += uint64(n)
			if err := s.Channel.Send(&protocol.PlainPayload{FileChunk: chunk}); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if err := s.Channel.Send(&protocol.PlainPayload{FileChunk: &protocol.FileTransferChunk{Offset: offset, Eof: true}}); err != nil {
		return err
	}

	// await final result
	final, err := s.awaitFileResult()
	if err != nil {
		return err
	}
	if !final.Success {
		return errors.New(final.Message)
	}
	return nil
}

// downloadFile pulls a remote file to the local filesystem via an established client session.
func (s *clientSession) downloadFile(localPath, remotePath string) error {
	if localPath == "" {
		return errors.New("missing local destination path")
	}
	if info, err := os.Stat(localPath); err == nil && info.IsDir() {
		return fmt.Errorf("%s is a directory", localPath)
	}

	// send download request
	if err := s.Channel.Send(&protocol.PlainPayload{FileRequest: &protocol.FileTransferRequest{Direction: protocol.FileDirection_FILE_DIRECTION_DOWNLOAD, Path: remotePath}}); err != nil {
		return err
	}

	// await server readiness
	start, err := s.awaitFileResult()
	if err != nil {
		return err
	}
	if !start.Success {
		return errors.New(start.Message)
	}
	perm := os.FileMode(start.Perm)
	if perm == 0 {
		perm = 0o600
	}

	// prepare local file
	if err := ensureLocalParent(localPath); err != nil {
		return err
	}
	file, err := os.OpenFile(localPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer file.Close()

	// receive file contents
	var offset uint64
	for {
		payload, err := s.Channel.Recv()
		if err != nil {
			return err
		}
		if payload.FileChunk != nil {
			chunk := payload.FileChunk
			if chunk.Offset != offset {
				return fmt.Errorf("unexpected chunk offset %d (expected %d)", chunk.Offset, offset)
			}
			if len(chunk.Data) > 0 {
				if _, err := file.Write(chunk.Data); err != nil {
					return err
				}
				offset += uint64(len(chunk.Data))
			}
			if chunk.Eof {
				break
			}
			continue
		}
		if payload.FileResult != nil && payload.FileResult.Done {
			if !payload.FileResult.Success {
				return errors.New(payload.FileResult.Message)
			}
			return nil
		}
	}

	// finalize file
	if err := file.Sync(); err != nil {
		return err
	}

	// await final result
	final, err := s.awaitFileResult()
	if err != nil {
		return err
	}
	if !final.Success {
		return errors.New(final.Message)
	}
	return nil
}

func (s *clientSession) awaitFileResult() (*protocol.FileTransferResult, error) {
	for {
		payload, err := s.Channel.Recv()
		if err != nil {
			return nil, err
		}
		if payload.FileResult != nil {
			return payload.FileResult, nil
		}
	}
}

// handleFileTransferSession orchestrates upload/download flows for copy mode clients.
func (s *serverSession) handleFileTransferSession() error {
	payload, err := s.Channel.Recv()
	if err != nil {
		return err
	}
	req := payload.FileRequest
	if req == nil {
		_ = s.sendCopyResult(false, "expected file transfer request", 0, true, 0)
		return errors.New("copy: missing file transfer request")
	}

	// dispatch based on direction
	switch req.Direction {
	case protocol.FileDirection_FILE_DIRECTION_UPLOAD:
		return s.handleUploadTransfer(req)
	case protocol.FileDirection_FILE_DIRECTION_DOWNLOAD:
		return s.handleDownloadTransfer(req)
	default:
		_ = s.sendCopyResult(false, fmt.Sprintf("unsupported direction %v", req.Direction), 0, true, 0)
		return fmt.Errorf("copy: unsupported direction %v", req.Direction)
	}
}

// handleUploadTransfer processes an upload request from the client and writes the incoming file data to the server's filesystem.
func (s *serverSession) handleUploadTransfer(req *protocol.FileTransferRequest) error {
	// sanitize and prepare destination file
	path, err := sanitizeCopyPath(req.Path)
	if err != nil {
		_ = s.sendCopyResult(false, err.Error(), 0, true, 0)
		return err
	}
	perm := os.FileMode(req.Perm)
	if perm == 0 {
		perm = 0o600
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		_ = s.sendCopyResult(false, err.Error(), 0, true, uint32(perm))
		return err
	}
	defer file.Close()

	// signal readiness to receive file data
	if err := s.sendCopyResult(true, "ready", req.Size, false, uint32(perm)); err != nil {
		return err
	}

	// receive file data
	var written uint64
	for {
		payload, err := s.Channel.Recv()
		if err != nil {
			_ = s.sendCopyResult(false, err.Error(), written, true, uint32(perm))
			return err
		}
		chunk := payload.FileChunk
		if chunk == nil {
			msg := "missing file chunk"
			_ = s.sendCopyResult(false, msg, written, true, uint32(perm))
			return errors.New("copy: missing file chunk")
		}
		if chunk.Offset != written {
			msg := fmt.Sprintf("unexpected chunk offset %d (expected %d)", chunk.Offset, written)
			_ = s.sendCopyResult(false, msg, written, true, uint32(perm))
			return errors.New(msg)
		}
		if len(chunk.Data) > 0 {
			if _, err := file.Write(chunk.Data); err != nil {
				_ = s.sendCopyResult(false, err.Error(), written, true, uint32(perm))
				return err
			}
			written += uint64(len(chunk.Data))
		}
		if chunk.Eof {
			break
		}
	}

	// finalize file
	if err := file.Sync(); err != nil {
		_ = s.sendCopyResult(false, err.Error(), written, true, uint32(perm))
		return err
	}

	// send completion result
	return s.sendCopyResult(true, "upload complete", written, true, uint32(perm))
}

// handleDownloadTransfer processes a download request from the client and streams the requested file data back to the client.
func (s *serverSession) handleDownloadTransfer(req *protocol.FileTransferRequest) error {
	// sanitize and open source file
	path, err := sanitizeCopyPath(req.Path)
	if err != nil {
		_ = s.sendCopyResult(false, err.Error(), 0, true, 0)
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		_ = s.sendCopyResult(false, err.Error(), 0, true, 0)
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		_ = s.sendCopyResult(false, err.Error(), 0, true, 0)
		return err
	}
	size := uint64(info.Size())
	perm := uint32(info.Mode().Perm())
	if err := s.sendCopyResult(true, "starting download", size, false, perm); err != nil {
		return err
	}

	// stream file contents
	buf := make([]byte, fileCopyBufferSize)
	var offset uint64
	for {
		n, readErr := file.Read(buf)
		if n > 0 {
			chunk := &protocol.FileTransferChunk{Data: append([]byte(nil), buf[:n]...), Offset: offset}
			offset += uint64(n)
			if err := s.Channel.Send(&protocol.PlainPayload{FileChunk: chunk}); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = s.sendCopyResult(false, readErr.Error(), offset, true, perm)
			return readErr
		}
	}

	// send EOF chunk
	if err := s.Channel.Send(&protocol.PlainPayload{FileChunk: &protocol.FileTransferChunk{Offset: offset, Eof: true}}); err != nil {
		return err
	}
	return s.sendCopyResult(true, "download complete", offset, true, perm)
}

// sendCopyResult sends a file transfer result message to the client.
func (s *serverSession) sendCopyResult(ok bool, message string, size uint64, done bool, perm uint32) error {
	res := &protocol.FileTransferResult{Success: ok, Message: message, Size: size, Done: done, Perm: perm}
	return s.Channel.Send(&protocol.PlainPayload{FileResult: res})
}

// sanitizeCopyPath cleans and validates a file path for copy operations.
func sanitizeCopyPath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", errors.New("empty path")
	}
	return filepath.Clean(trimmed), nil
}

// ensureLocalParent creates parent directories for a given local path if they do not already exist.
func ensureLocalParent(path string) error {
	dir := filepath.Dir(path)
	if dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

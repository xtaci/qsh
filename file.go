package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	cli "github.com/urfave/cli/v2"
	"github.com/xtaci/hppk"
	"github.com/xtaci/qpp"
	qcrypto "github.com/xtaci/qsh/crypto"
	"github.com/xtaci/qsh/protocol"
)

type remoteTarget struct {
	clientID string
	host     string
	path     string
}

func runCopyCommand(c *cli.Context) error {
	if c.NArg() != 2 {
		return exitWithExample("copy command requires a source and destination", exampleCopy)
	}
	identity := c.String("identity")
	if identity == "" {
		return exitWithExample("copy command requires --identity", exampleCopy)
	}
	srcArg := strings.TrimSpace(c.Args().Get(0))
	dstArg := strings.TrimSpace(c.Args().Get(1))
	if srcArg == "" || dstArg == "" {
		return exitWithExample("copy command requires non-empty source and destination", exampleCopy)
	}

	srcRemote, isSrcRemote, err := parseRemoteTarget(srcArg)
	if err != nil {
		return err
	}
	dstRemote, isDstRemote, err := parseRemoteTarget(dstArg)
	if err != nil {
		return err
	}
	if isSrcRemote == isDstRemote {
		return exitWithExample("copy command requires exactly one remote endpoint", exampleCopy)
	}

	var remote remoteTarget
	var direction protocol.FileDirection
	var localPath string
	if isSrcRemote {
		remote = srcRemote
		direction = protocol.FileDirection_FILE_DIRECTION_DOWNLOAD
		localPath = dstArg
	} else {
		remote = dstRemote
		direction = protocol.FileDirection_FILE_DIRECTION_UPLOAD
		localPath = srcArg
	}
	if remote.clientID == "" {
		remote.clientID = strings.TrimSpace(c.String("id"))
	}
	if remote.clientID == "" {
		return exitWithExample("copy command requires a client identifier", exampleCopy)
	}
	if remote.host == "" {
		return exitWithExample("copy command requires a remote host", exampleCopy)
	}
	priv, err := qcrypto.LoadPrivateKey(identity)
	if err != nil {
		return err
	}

	addr := remote.host
	if !strings.Contains(addr, ":") {
		port := c.Int("port")
		if port <= 0 {
			port = 2222
		}
		addr = fmt.Sprintf("%s:%d", addr, port)
	}
	return executeCopySession(addr, priv, remote.clientID, direction, localPath, remote.path)
}

func executeCopySession(addr string, priv *hppk.PrivateKey, clientID string, direction protocol.FileDirection, localPath, remotePath string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	session, err := performClientHandshake(conn, priv, clientID, protocol.ClientMode_CLIENT_MODE_COPY)
	if err != nil {
		return err
	}
	switch direction {
	case protocol.FileDirection_FILE_DIRECTION_UPLOAD:
		return clientUploadFile(conn, session.Writer, session.RecvPad, session.RecvMac, localPath, remotePath)
	case protocol.FileDirection_FILE_DIRECTION_DOWNLOAD:
		return clientDownloadFile(conn, session.Writer, session.RecvPad, session.RecvMac, localPath, remotePath)
	default:
		return errors.New("unsupported copy direction")
	}
}

func clientUploadFile(conn net.Conn, writer *encryptedWriter, recv *qpp.QuantumPermutationPad, recvMac []byte, localPath, remotePath string) error {
	info, err := os.Stat(localPath)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", localPath)
	}
	perm := uint32(info.Mode().Perm())
	req := &protocol.FileTransferRequest{
		Direction: protocol.FileDirection_FILE_DIRECTION_UPLOAD,
		Path:      remotePath,
		Size:      uint64(info.Size()),
		Perm:      perm,
	}
	if err := writer.Send(&protocol.PlainPayload{FileRequest: req}); err != nil {
		return err
	}
	ready, err := awaitFileResult(conn, recv, recvMac)
	if err != nil {
		return err
	}
	if !ready.Success {
		return errors.New(ready.Message)
	}
	file, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer file.Close()
	buf := make([]byte, 32*1024)
	var offset uint64
	for {
		n, readErr := file.Read(buf)
		if n > 0 {
			chunk := &protocol.FileTransferChunk{Data: append([]byte(nil), buf[:n]...), Offset: offset}
			offset += uint64(n)
			if err := writer.Send(&protocol.PlainPayload{FileChunk: chunk}); err != nil {
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
	if err := writer.Send(&protocol.PlainPayload{FileChunk: &protocol.FileTransferChunk{Offset: offset, Eof: true}}); err != nil {
		return err
	}
	final, err := awaitFileResult(conn, recv, recvMac)
	if err != nil {
		return err
	}
	if !final.Success {
		return errors.New(final.Message)
	}
	return nil
}

func clientDownloadFile(conn net.Conn, writer *encryptedWriter, recv *qpp.QuantumPermutationPad, recvMac []byte, localPath, remotePath string) error {
	if localPath == "" {
		return errors.New("missing local destination path")
	}
	if info, err := os.Stat(localPath); err == nil && info.IsDir() {
		return fmt.Errorf("%s is a directory", localPath)
	}
	if err := writer.Send(&protocol.PlainPayload{FileRequest: &protocol.FileTransferRequest{Direction: protocol.FileDirection_FILE_DIRECTION_DOWNLOAD, Path: remotePath}}); err != nil {
		return err
	}
	start, err := awaitFileResult(conn, recv, recvMac)
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
	if err := ensureLocalParent(localPath); err != nil {
		return err
	}
	file, err := os.OpenFile(localPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer file.Close()
	var offset uint64
	for {
		payload, err := receivePayload(conn, recv, recvMac)
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
	if err := file.Sync(); err != nil {
		return err
	}
	final, err := awaitFileResult(conn, recv, recvMac)
	if err != nil {
		return err
	}
	if !final.Success {
		return errors.New(final.Message)
	}
	return nil
}

func awaitFileResult(conn net.Conn, recv *qpp.QuantumPermutationPad, recvMac []byte) (*protocol.FileTransferResult, error) {
	for {
		payload, err := receivePayload(conn, recv, recvMac)
		if err != nil {
			return nil, err
		}
		if payload.FileResult != nil {
			return payload.FileResult, nil
		}
	}
}

func ensureLocalParent(path string) error {
	dir := filepath.Dir(path)
	if dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

func parseRemoteTarget(arg string) (remoteTarget, bool, error) {
	trimmed := strings.TrimSpace(arg)
	if trimmed == "" {
		return remoteTarget{}, false, nil
	}
	at := strings.Index(trimmed, "@")
	if at == -1 {
		return remoteTarget{}, false, nil
	}
	colon := strings.Index(trimmed[at+1:], ":")
	if colon == -1 {
		return remoteTarget{}, false, fmt.Errorf("remote specification %q missing path separator ':'", arg)
	}
	colon += at + 1
	clientID := strings.TrimSpace(trimmed[:at])
	host := strings.TrimSpace(trimmed[at+1 : colon])
	path := trimmed[colon+1:]
	if clientID == "" {
		return remoteTarget{}, false, fmt.Errorf("remote specification %q missing client id", arg)
	}
	if host == "" {
		return remoteTarget{}, false, fmt.Errorf("remote specification %q missing host", arg)
	}
	if path == "" {
		return remoteTarget{}, false, fmt.Errorf("remote specification %q missing path", arg)
	}
	return remoteTarget{clientID: clientID, host: host, path: path}, true, nil
}

// handleFileTransferSession orchestrates upload/download flows for copy mode clients.
func handleFileTransferSession(conn net.Conn, writer *encryptedWriter, recvQPP *qpp.QuantumPermutationPad, recvMac []byte) error {
	payload, err := receivePayload(conn, recvQPP, recvMac)
	if err != nil {
		return err
	}
	req := payload.FileRequest
	if req == nil {
		_ = sendCopyResult(writer, false, "expected file transfer request", 0, true, 0)
		return errors.New("copy: missing file transfer request")
	}
	switch req.Direction {
	case protocol.FileDirection_FILE_DIRECTION_UPLOAD:
		return handleUploadTransfer(conn, writer, recvQPP, recvMac, req)
	case protocol.FileDirection_FILE_DIRECTION_DOWNLOAD:
		return handleDownloadTransfer(writer, req)
	default:
		_ = sendCopyResult(writer, false, fmt.Sprintf("unsupported direction %v", req.Direction), 0, true, 0)
		return fmt.Errorf("copy: unsupported direction %v", req.Direction)
	}
}

func handleUploadTransfer(conn net.Conn, writer *encryptedWriter, recvQPP *qpp.QuantumPermutationPad, recvMac []byte, req *protocol.FileTransferRequest) error {
	path, err := sanitizeCopyPath(req.Path)
	if err != nil {
		_ = sendCopyResult(writer, false, err.Error(), 0, true, 0)
		return err
	}
	perm := os.FileMode(req.Perm)
	if perm == 0 {
		perm = 0o600
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		_ = sendCopyResult(writer, false, err.Error(), 0, true, uint32(perm))
		return err
	}
	defer file.Close()
	if err := sendCopyResult(writer, true, "ready", req.Size, false, uint32(perm)); err != nil {
		return err
	}
	var written uint64
	for {
		payload, err := receivePayload(conn, recvQPP, recvMac)
		if err != nil {
			_ = sendCopyResult(writer, false, err.Error(), written, true, uint32(perm))
			return err
		}
		chunk := payload.FileChunk
		if chunk == nil {
			msg := "missing file chunk"
			_ = sendCopyResult(writer, false, msg, written, true, uint32(perm))
			return errors.New("copy: missing file chunk")
		}
		if chunk.Offset != written {
			msg := fmt.Sprintf("unexpected chunk offset %d (expected %d)", chunk.Offset, written)
			_ = sendCopyResult(writer, false, msg, written, true, uint32(perm))
			return errors.New(msg)
		}
		if len(chunk.Data) > 0 {
			if _, err := file.Write(chunk.Data); err != nil {
				_ = sendCopyResult(writer, false, err.Error(), written, true, uint32(perm))
				return err
			}
			written += uint64(len(chunk.Data))
		}
		if chunk.Eof {
			break
		}
	}
	if err := file.Sync(); err != nil {
		_ = sendCopyResult(writer, false, err.Error(), written, true, uint32(perm))
		return err
	}
	return sendCopyResult(writer, true, "upload complete", written, true, uint32(perm))
}

func handleDownloadTransfer(writer *encryptedWriter, req *protocol.FileTransferRequest) error {
	path, err := sanitizeCopyPath(req.Path)
	if err != nil {
		_ = sendCopyResult(writer, false, err.Error(), 0, true, 0)
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		_ = sendCopyResult(writer, false, err.Error(), 0, true, 0)
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		_ = sendCopyResult(writer, false, err.Error(), 0, true, 0)
		return err
	}
	size := uint64(info.Size())
	perm := uint32(info.Mode().Perm())
	if err := sendCopyResult(writer, true, "starting download", size, false, perm); err != nil {
		return err
	}
	buf := make([]byte, 32*1024)
	var offset uint64
	for {
		n, readErr := file.Read(buf)
		if n > 0 {
			chunk := &protocol.FileTransferChunk{Data: append([]byte(nil), buf[:n]...), Offset: offset}
			offset += uint64(n)
			if err := writer.Send(&protocol.PlainPayload{FileChunk: chunk}); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = sendCopyResult(writer, false, readErr.Error(), offset, true, perm)
			return readErr
		}
	}
	if err := writer.Send(&protocol.PlainPayload{FileChunk: &protocol.FileTransferChunk{Offset: offset, Eof: true}}); err != nil {
		return err
	}
	return sendCopyResult(writer, true, "download complete", offset, true, perm)
}

func sanitizeCopyPath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", errors.New("empty path")
	}
	return filepath.Clean(trimmed), nil
}

func sendCopyResult(writer *encryptedWriter, ok bool, message string, size uint64, done bool, perm uint32) error {
	res := &protocol.FileTransferResult{Success: ok, Message: message, Size: size, Done: done, Perm: perm}
	return writer.Send(&protocol.PlainPayload{FileResult: res})
}

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
	priv, err := loadPrivateKey(identity)
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
	writer, recv, recvMac, err := performClientHandshake(conn, priv, clientID, protocol.ClientMode_CLIENT_MODE_COPY)
	if err != nil {
		return err
	}
	switch direction {
	case protocol.FileDirection_FILE_DIRECTION_UPLOAD:
		return clientUploadFile(conn, writer, recv, recvMac, localPath, remotePath)
	case protocol.FileDirection_FILE_DIRECTION_DOWNLOAD:
		return clientDownloadFile(conn, writer, recv, recvMac, localPath, remotePath)
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

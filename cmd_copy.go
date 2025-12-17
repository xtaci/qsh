package main

import (
	"fmt"
	"net"
	"strings"

	cli "github.com/urfave/cli/v2"
	"github.com/xtaci/hppk"
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

	// determine direction and prepare parameters
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

	// validate remote parameters
	if remote.clientID == "" {
		remote.clientID = strings.TrimSpace(c.String("id"))
		if remote.clientID == "" {
			return exitWithExample("copy command requires a client identifier", exampleCopy)
		}
	}
	if remote.host == "" {
		return exitWithExample("copy command requires a remote host", exampleCopy)
	}

	// load private key
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

// executeCopySession establishes a client session and performs the requested file transfer.
func executeCopySession(addr string, priv *hppk.PrivateKey, clientID string, direction protocol.FileDirection, localPath, remotePath string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// perform handshake
	session, err := performClientHandshake(conn, priv, clientID, protocol.ClientMode_CLIENT_MODE_COPY)
	if err != nil {
		return err
	}

	// perform file transfer based on direction
	switch direction {
	case protocol.FileDirection_FILE_DIRECTION_UPLOAD:
		return session.uploadFile(localPath, remotePath)
	case protocol.FileDirection_FILE_DIRECTION_DOWNLOAD:
		return session.downloadFile(localPath, remotePath)
	default:
		return fmt.Errorf("unsupported copy direction: %v", direction)
	}
}

// parseRemoteTarget parses a remote target specification of the form "clientID@host:path".
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

package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"github.com/xtaci/qsh/protocol"
	"golang.org/x/term"
)

// ==============================================================//
// Client-side PTY handling
// ==============================================================//

func (s *clientSession) startInteractiveShell() error {
	// Set terminal to raw mode
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err == nil {
		defer term.Restore(int(os.Stdin.Fd()), oldState)
	}

	// Send initial terminal size
	rows, cols := s.getWinSize()
	_ = s.Channel.Send(&protocol.PlainPayload{Resize: &protocol.Resize{Rows: uint32(rows), Cols: uint32(cols)}})

	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }

	// Start terminal resize handler goroutine
	go s.handleClientResize(done)

	// Start IO forwarding
	errCh := make(chan error, 2)
	go func() { errCh <- s.forwardStdIn() }()
	go func() { errCh <- s.readServerOutput() }()

	// Wait for any IO error
	err = <-errCh
	stop()
	return err
}

// forwardStdIn encrypts and forwards local keystrokes to the server.
func (s *clientSession) forwardStdIn() error {
	buf := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			if sendErr := s.Channel.Send(&protocol.PlainPayload{Stream: chunk}); sendErr != nil {
				return sendErr
			}
		}
		if err != nil {
			return err
		}
	}
}

// readServerOutput decrypts server payloads and writes them to stdout.
func (s *clientSession) readServerOutput() error {
	for {
		payload, err := s.Channel.Recv()
		if err != nil {
			return err
		}
		if len(payload.Stream) > 0 {
			if _, err := os.Stdout.Write(payload.Stream); err != nil {
				return err
			}
		}
	}
}

// handleClientResize pushes terminal size updates to the remote PTY.
func (s *clientSession) handleClientResize(done <-chan struct{}) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	defer signal.Stop(sigCh)

	for {
		select {
		case <-done:
			return
		case <-sigCh:
			rows, cols := s.getWinSize()
			_ = s.Channel.Send(&protocol.PlainPayload{Resize: &protocol.Resize{Rows: uint32(rows), Cols: uint32(cols)}})
		}
	}
}

// getWinSize returns the caller TTY dimensions, falling back to 80x24.
func (s *clientSession) getWinSize() (rows, cols uint16) {
	w, h, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		return 24, 80
	}
	return uint16(h), uint16(w)
}

//==============================================================//
// Server-side PTY handling
//==============================================================//

// handleInteractiveShell bridges the remote PTY with the encrypted stream.
func (s *serverSession) handleInteractiveShell() error {
	cmd := exec.Command("/bin/sh")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return err
	}
	defer ptmx.Close()

	errCh := make(chan error, 2)
	go func() { errCh <- s.forwardPTYToClient(ptmx) }()
	go func() { errCh <- s.forwardClientToPTY(ptmx) }()

	err = <-errCh
	s.Conn.Close()
	cmd.Process.Kill()
	cmd.Wait()
	return err
}

// forwardPTYToClient streams PTY output toward the client.
func (s *serverSession) forwardPTYToClient(ptmx *os.File) error {
	buf := make([]byte, 4096)
	for {
		n, err := ptmx.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			if sendErr := s.Channel.Send(&protocol.PlainPayload{Stream: chunk}); sendErr != nil {
				return sendErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// forwardClientToPTY feeds decrypted client data back into the PTY.
func (s *serverSession) forwardClientToPTY(ptmx *os.File) error {
	for {
		payload, err := s.Channel.Recv()
		if err != nil {
			return err
		}
		if len(payload.Stream) > 0 {
			if _, err := ptmx.Write(payload.Stream); err != nil {
				return err
			}
		}
		if payload.Resize != nil {
			s.applyResize(ptmx, payload.Resize)
		}
	}
}

// applyResize resizes the PTY; errors are ignored because resize is best-effort.
func (s *serverSession) applyResize(ptmx *os.File, resize *protocol.Resize) {
	rows := uint16(resize.Rows)
	cols := uint16(resize.Cols)
	_ = pty.Setsize(ptmx, &pty.Winsize{Rows: rows, Cols: cols})
}

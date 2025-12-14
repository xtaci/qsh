package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/term"
)

/* ================= CONTROL PROTOCOL ================= */

func sendResize(w io.Writer, rows, cols uint16) {
	buf := []byte{
		0xFF,
		0x01,
		byte(rows >> 8), byte(rows),
		byte(cols >> 8), byte(cols),
	}
	w.Write(buf)
}

func getWinsize() (rows, cols uint16) {
	w, h, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		return 24, 80
	}
	return uint16(h), uint16(w)
}

/* ================= SERVER ================= */

func runServer(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("listening on", addr)

	for {
		conn, _ := ln.Accept()
		go handleServerConn(conn)
	}
}

func handleServerConn(conn net.Conn) {
	defer conn.Close()

	cmd := exec.Command("/bin/sh")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return
	}
	defer ptmx.Close()

	go proxyInput(conn, ptmx)
	io.Copy(conn, ptmx)

	cmd.Wait()
}

func proxyInput(r io.Reader, ptmx *os.File) {
	buf := make([]byte, 1)

	for {
		_, err := r.Read(buf)
		if err != nil {
			return
		}

		if buf[0] == 0xFF {
			handleControl(r, ptmx)
			continue
		}

		ptmx.Write(buf)
	}
}

func handleControl(r io.Reader, ptmx *os.File) {
	hdr := make([]byte, 1)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return
	}

	if hdr[0] == 0x01 {
		payload := make([]byte, 4)
		if _, err := io.ReadFull(r, payload); err != nil {
			return
		}

		rows := uint16(payload[0])<<8 | uint16(payload[1])
		cols := uint16(payload[2])<<8 | uint16(payload[3])

		pty.Setsize(ptmx, &pty.Winsize{
			Rows: rows,
			Cols: cols,
		})
	}
}

/* ================= CLIENT ================= */

func runClient(addr string) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err == nil {
		defer term.Restore(int(os.Stdin.Fd()), oldState)
	}

	rows, cols := getWinsize()
	sendResize(conn, rows, cols)

	go handleResize(conn)
	go io.Copy(conn, os.Stdin)
	io.Copy(os.Stdout, conn)
}

func handleResize(w io.Writer) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)

	for range ch {
		rows, cols := getWinsize()
		sendResize(w, rows, cols)
	}
}

/* ================= MAIN ================= */

func main() {
	server := flag.String("s", "", "server mode")
	flag.Parse()

	if *server != "" {
		runServer(*server)
		return
	}

	if flag.NArg() != 1 {
		fmt.Println("usage:")
		fmt.Println("  qsh -s ip:port")
		fmt.Println("  qsh ip:port")
		return
	}

	runClient(flag.Arg(0))
}

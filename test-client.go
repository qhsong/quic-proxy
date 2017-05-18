package main

import (
	"crypto/tls"
	"io"
	"log"

	"net"

	quic "github.com/lucas-clemente/quic-go"
)

const addr = "server:4242"

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	ln, err := net.Listen("tcp", ":5201")
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go clientMain(conn)
	}
}

func clientMain(conn net.Conn) error {
	log.Println("Open client")
	cfgClient := &quic.Config{
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	}
	session, err := quic.DialAddr(addr, cfgClient)
	if err != nil {
		return err
	}

	stream, err := session.OpenStream()
	if err != nil {
		return err
	}
	log.Println("Start pipeline")
	go pipeline(stream, loggingWriter{conn})
	pipeline(conn, stream)
	return nil
}

func pipeline(origin io.Reader, target io.Writer) {
	for {
		io.Copy(target, origin)
	}
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	//fmt.Printf("Server: Got '%s'\n", string(b))
	return w.Writer.Write(b)
}

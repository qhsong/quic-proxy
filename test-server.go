package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"

	quic "github.com/lucas-clemente/quic-go"
)

const addr = ":4242"

const message = "foobar"

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	conn, err := net.Dial("tcp", "localhost:80")
	if err != nil {
		log.Fatal(err)
	}
	echoServer(conn)
}

// Start a server that echos all data on the first stream opened by the client
func echoServer(conn net.Conn) error {
	cfgServer := &quic.Config{
		TLSConfig: generateTLSConfig(),
		ConnState: func(sess quic.Session, cs quic.ConnState) {
			// Ignore unless the handshake is finished
			if cs != quic.ConnStateForwardSecure {
				return
			}
			go func() {
				stream, err := sess.AcceptStream()
				if err != nil {
					panic(err)
				}
				// Echo through the loggingWriter
				go pipeline(conn, stream)
				go pipeline(stream, conn)
			}()
		},
	}
	listener, err := quic.ListenAddr(addr, cfgServer)
	if err != nil {
		return err
	}
	return listener.Serve()
}

func clientMain() error {
	cfgClient := &quic.Config{
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	}
	session, err := quic.DialAddr(addr, cfgClient)
	if err != nil {
		return err
	}

	stream, err := session.OpenStreamSync()
	if err != nil {
		return err
	}

	fmt.Printf("Client: Sending '%s'\n", message)
	_, err = stream.Write([]byte(message))
	if err != nil {
		return err
	}

	buf := make([]byte, len(message))
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		return err
	}
	fmt.Printf("Client: Got '%s'\n", buf)

	return nil
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}

func pipeline(origin io.Reader, target io.Writer) {
	for {
		io.Copy(loggingWriter{target}, origin)
	}
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	//fmt.Printf("Server: Got '%s'\n", string(b))
	return w.Writer.Write(b)
}

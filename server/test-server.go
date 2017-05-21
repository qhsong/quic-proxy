package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"

	"../proxy"
	quic "github.com/lucas-clemente/quic-go"
)

const addr = ":4242"

func main() {
	StartServer()
}

// Start a server that echos all data on the first stream opened by the client
func StartServer() error {
	cfgServer := &quic.Config{
		TLSConfig: generateTLSConfig(),
	}
	listener, err := quic.ListenAddr(addr, cfgServer)
	if err != nil {
		return err
	}

	log.Println("start listen", addr)
	for {
		sess, err := listener.Accept()
		if err != nil {

		}
		go func() {
			stream, err := sess.AcceptStream()
			if err != nil {
				panic(err)
			}

			result, err := proxy.ReadAuthInfo(stream)
			if err != nil {
				log.Println(err)
			}
			conn, err := net.Dial("tcp", result.EndPoint+":"+result.Port)
			if err != nil {
				proxy.HandleServerAuthFailed(stream)
				log.Println("Unable to connect", result.EndPoint+":"+result.Port)
			}

			proxy.HandleServerAuthSuccess(stream)

			// Echo through the loggingWriter
			go pipeline(conn, stream)
			go pipeline(stream, conn)
		}()
	}
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

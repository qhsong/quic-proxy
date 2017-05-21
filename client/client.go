package main

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"strconv"
	"strings"

	"../proxy"
	quic "github.com/lucas-clemente/quic-go"
)

var (
	errAddrType      = errors.New("socks addr type not supported")
	errVer           = errors.New("socks version not supported")
	errMethod        = errors.New("socks only support 1 method now")
	errAuthExtraData = errors.New("socks authentication get extra data")
	errReqExtraData  = errors.New("socks request get extra data")
	errCmd           = errors.New("socks command not supported")
)

const (
	socksVer5       = 5
	socksCmdConnect = 1
)

type clientConfig struct {
	Server    string
	Port      int
	LocalPort int
}

var config clientConfig

const serverAddr = "server:4242"

func main() {
	flag.StringVar(&config.Server, "s", "", "remote server address")
	flag.IntVar(&config.Port, "p", 10241, "remote server port")
	flag.IntVar(&config.LocalPort, "l", 2093, "local listen port")

	flag.Parse()

	if config.Server == "" {
		log.Println("Unable to read remote server address")
	}

	run()
}

func run() {

	ln, err := net.Listen("tcp", ":"+strconv.Itoa(config.LocalPort))
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Starting local sock5 server at ", ":"+strconv.Itoa(config.LocalPort))
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		go handleConnection(conn)
	}

}

func handleConnection(conn net.Conn) {
	closed := false
	defer func() {
		if !closed {
			conn.Close()
		}
	}()

	err := handShake(conn)
	if err != nil {
		log.Println("socks handshake:", err)
		return
	}
	_, host, err := getRequest(conn)
	EndPoint := strings.Split(host, ":")

	cfgClient := &quic.Config{
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	}
	session, err := quic.DialAddr(serverAddr, cfgClient)
	if err != nil {
		return
	}
	// Sending connection established message immediately to client.
	// This some round trip time for creating socks connection with the client.
	// But if connection failed, the client will get connection reset error.
	stream, err := session.OpenStream()
	if err != nil {
		return
	}

	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
	if err != nil {
		log.Println("send connection confirmation:", err)
		return
	}

	log.Println("Start pipeline")

	proxy.RequestClientAuth(stream, "test", EndPoint[0], EndPoint[1])
	go proxy.PipeThenClose(stream, conn)
	proxy.PipeThenClose(conn, stream)

	stream.Close()
	conn.Close()

}

func handShake(conn net.Conn) (err error) {
	const (
		idVer     = 0
		idNmethod = 1
	)

	buf := make([]byte, 258)

	n, err := io.ReadAtLeast(conn, buf, idNmethod+1)
	if err != nil {
		return err
	}
	if buf[idVer] != socksVer5 {
		return errVer
	}

	nmethod := int(buf[idNmethod])
	msgLen := nmethod + 2
	if n == msgLen {

	} else if n < msgLen {
		if _, err = io.ReadFull(conn, buf[n:msgLen]); err != nil {
			return
		}
	} else {
		return errAuthExtraData
	}

	_, err = conn.Write([]byte{socksVer5, 0})
	return
}

func getRequest(conn net.Conn) (rawaddr []byte, host string, err error) {
	const (
		idVer   = 0
		idCmd   = 1
		idType  = 3 // address type index
		idIP0   = 4 // ip addres start index
		idDmLen = 4 // domain address length index
		idDm0   = 5 // domain address start index

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address

		lenIPv4   = 3 + 1 + net.IPv4len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
		lenIPv6   = 3 + 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
		lenDmBase = 3 + 1 + 1 + 2           // 3 + 1addrType + 1addrLen + 2port, plus addrLen
	)
	// refer to getRequest in server.go for why set buffer size to 263
	buf := make([]byte, 263)
	var n int
	// read till we get possible domain length field
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		return
	}
	// check version and cmd
	if buf[idVer] != socksVer5 {
		err = errVer
		return
	}
	if buf[idCmd] != socksCmdConnect {
		err = errCmd
		return
	}

	reqLen := -1
	switch buf[idType] {
	case typeIPv4:
		reqLen = lenIPv4
	case typeIPv6:
		reqLen = lenIPv6
	case typeDm:
		reqLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = errAddrType
		return
	}

	if n == reqLen {
		// common case, do nothing
	} else if n < reqLen { // rare case
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else {
		err = errReqExtraData
		return
	}

	rawaddr = buf[idType:reqLen]

	switch buf[idType] {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	port := binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))

	return
}

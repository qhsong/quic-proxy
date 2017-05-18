package proxy

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"net"

	quic "github.com/lucas-clemente/quic-go"
)

const (
	AuthHeader = 0xdf
	md5Len     = md5.Size
)

type AuthPacket struct {
	Password string
	EndPoint string
	Port     string
}

func (p *AuthPacket) Serailize() (result []byte) {
	if p.Password == "" || p.EndPoint == "" || p.Port == "" {
		return
	}
	result[0] = AuthHeader
	md5Passwd := md5.Sum([]byte(p.Password))
	len := md5Len + len(p.EndPoint) + len(p.Port) + 1
	var tmpLen []byte
	binary.LittleEndian.PutUint32(tmpLen, uint32(len))
	copy(result[1:], tmpLen)
	copy(result[5:md5Len], md5Passwd[:])
	copy(result[5+md5Len:], p.EndPoint+":"+p.Port)
	return
}

func NewAuthPacket(password, end, port string) *AuthPacket {

	return &AuthPacket{
		Password: password,
		EndPoint: end,
		Port:     port,
	}
}

func auth(session quic.Session, password string, ip net.IP, host string, port string) (bool, error) {
	var packet *AuthPacket
	if len(host) != 0 {
		packet = NewAuthPacket(password, host, port)
	} else {
		packet = NewAuthPacket(password, ip.String(), port)
	}
	bPacket := packet.Serailize()
	if len(bPacket) == 0 {
		return false, errors.New("Unable to create Auth packet")
	}
	steam, err := session.OpenStream()
	if err != nil {
		return false, err
	}
	steam.Write(bPacket) //check Here
	return true, nil
}

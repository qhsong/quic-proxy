package proxy

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"strings"

	quic "github.com/lucas-clemente/quic-go"
)

const (
	AuthHeader         = 0xdf
	AuthResponseHeader = 0xde
	md5Len             = md5.Size
	ReplyLen           = 2
	MinAuthPacketSize  = 5 + md5.Size //1 flag + 4 len
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

	md5Passwd := md5.Sum([]byte(p.Password))
	ContentLen := md5Len + len(p.EndPoint) + len(p.Port) + 1
	var tmpLen []byte
	tmpLen = make([]byte, 4)
	binary.LittleEndian.PutUint32(tmpLen, uint32(ContentLen))
	result = make([]byte, 5+ContentLen)
	result[0] = AuthHeader
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

func NewAuthPacketFromBytes(result []byte) (*AuthPacket, error) {
	if len(result) < MinAuthPacketSize {
		return nil, errors.New("Can not got enough result")
	}
	if result[0] != AuthHeader {
		return nil, errors.New("Invaild pakcet header")
	}

	ContentLen := int(binary.LittleEndian.Uint32(result[1:5]))
	if ContentLen == 0 || ContentLen != len(result[5:]) {
		return nil, errors.New("Read packet length error")
	}

	Md5Password := string(result[5:md5Len])

	RemoteInfo := string(result[5+md5Len:])

	infos := strings.Split(RemoteInfo, ":")
	if len(infos) != 2 {
		return nil, errors.New("Invaild remote info")
	}

	_, err := strconv.Atoi(infos[1])
	if err != nil {
		return nil, errors.New("Invaild Port number")
	}

	return &AuthPacket{
		Password: Md5Password,
		EndPoint: infos[0],
		Port:     infos[1],
	}, nil
}

func RequestClientAuth(stream quic.Stream, password string, host string, port string) (bool, error) {
	var packet *AuthPacket
	if len(host) != 0 {
		packet = NewAuthPacket(password, host, port)
	}
	bPacket := packet.Serailize()
	if len(bPacket) == 0 {
		return false, errors.New("Unable to create Auth packet")
	}
	stream.Write(bPacket) //check Here

	response := make([]byte, 2)
	if _, err := io.ReadFull(stream, response); err != nil {
		return false, err
	}
	if response[0] == AuthResponseHeader && response[1] == 0x0 {
		return true, nil
	}
	return false, errors.New("Unable to Auth packet")

}

//Return true for test and will do it later.
func HandleServerAuthSuccess(stream quic.Stream) (bool, error) {
	if _, err := stream.Write([]byte{AuthResponseHeader, 0x0}); err != nil {
		return false, err
	}
	return true, nil
}

func HandleServerAuthFailed(stream quic.Stream) (bool, error) {
	if _, err := stream.Write([]byte{AuthResponseHeader, 0x1}); err != nil {
		return false, err
	}
	return true, nil
}

func ReadAuthInfo(stream quic.Stream) (*AuthPacket, error) {

	header := make([]byte, 5)
	_, err := stream.Read(header)
	if err != nil {
		return nil, err
	}

	PacketLen := int(binary.LittleEndian.Uint32(header[1:5]))
	body := make([]byte, PacketLen)
	_, err = io.ReadFull(stream, body)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 5+PacketLen)
	copy(packet, header)
	copy(packet[5:], body)
	APacket, err := NewAuthPacketFromBytes(packet)
	if err != nil {
		return nil, err
	}

	return APacket, nil
}

// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"github.com/herroxu/parser/gopacket"
)

// TLSHandshakeRecord defines the structure of a HandShake Record
type TLSHandshakeRecord struct {
	TLSRecordHeader
	HandleShakeRecords []HandShakeRecord
}

type HandShakeRecord struct {
	HandShakeType      byte
	HandShakeMsgLength uint32
	HandShakeMsg       []byte
	Buffer             []byte
}

// DecodeFromBytes decodes the slice into the TLS struct.
func (t *TLSHandshakeRecord) decodeFromBytes(h TLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// TLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length

	// encrypted handshake message
	if t.Length == 40 {
		var handShakeRecord HandShakeRecord
		handShakeRecord.Buffer = data[5:]
		handShakeRecord.HandShakeType = byte(44) // encrypted handshake message type
		handShakeRecord.HandShakeMsg = data
		t.HandleShakeRecords = append(t.HandleShakeRecords, handShakeRecord)
		return nil
	}

	err := t.decodeHandShake(data)
	if err != nil {
		return err
	}
	return nil
}

func (t *TLSHandshakeRecord) decodeHandShake(data []byte) error {
	if len(data) < 4 {
		return errors.New("handshake record too short")
	}
	//
	var handShakeRecord HandShakeRecord
	handShakeRecord.HandShakeType = data[0]
	handShakeRecord.HandShakeMsgLength = bytesToUint32(data[1:4])
	handShakeRecord.Buffer = data[:]

	hl := 4 // header length
	tl := hl + int(handShakeRecord.HandShakeMsgLength)
	if len(data) < tl {
		return errors.New("handle shake length mismatch")
	}
	handShakeRecord.HandShakeMsg = data[hl:tl]
	t.HandleShakeRecords = append(t.HandleShakeRecords, handShakeRecord)
	if len(data) == tl {
		return nil
	}
	return t.decodeHandShake(data[tl:])
}

func bytesToUint32(data []byte) uint32 {
	data = append([]byte{0}, data...)
	return binary.BigEndian.Uint32(data)
}

// clientHello 结构
type ClientHello struct {
	ClientVersion            uint16
	Random                   []byte
	SessionIdLength          uint8
	SessionId                []byte
	CipherSuitesLength       uint16
	CipherSuites             []byte
	CompressionMethodsLength uint8
	CompressionMethods       []byte
	ExtensionsLength         uint16
	Extensions               []byte
}

func (h *HandShakeRecord) ParseClientHello() (*ClientHello, error) {
	reader := bytes.NewReader(h.HandShakeMsg)
	var clientHello ClientHello
	// 解析ClientHello消息内容
	if err := binary.Read(reader, binary.BigEndian, &clientHello.ClientVersion); err != nil {
		return nil, err
	}
	clientHello.Random = make([]byte, 32)
	if err := binary.Read(reader, binary.BigEndian, &clientHello.Random); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &clientHello.SessionIdLength); err != nil {
		return nil, err
	}
	clientHello.SessionId = make([]byte, clientHello.SessionIdLength)
	if err := binary.Read(reader, binary.BigEndian, &clientHello.SessionId); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &clientHello.CipherSuitesLength); err != nil {
		return nil, err
	}
	clientHello.CipherSuites = make([]byte, clientHello.CipherSuitesLength)
	if err := binary.Read(reader, binary.BigEndian, &clientHello.CipherSuites); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &clientHello.CompressionMethodsLength); err != nil {
		return nil, err
	}
	clientHello.CompressionMethods = make([]byte, clientHello.CompressionMethodsLength)
	if err := binary.Read(reader, binary.BigEndian, &clientHello.CompressionMethods); err != nil {
		return nil, err
	}

	// Extensions
	if reader.Len() > 0 {
		if err := binary.Read(reader, binary.BigEndian, &clientHello.ExtensionsLength); err != nil {
			return nil, err
		}
		clientHello.Extensions = make([]byte, clientHello.ExtensionsLength)
		if err := binary.Read(reader, binary.BigEndian, &clientHello.Extensions); err != nil {
			return nil, err
		}
	}
	return &clientHello, nil
}

// serverHello 结构
type ServerHello struct {
	ProtocolVersion   uint16
	Random            [32]byte
	SessionIDLength   uint8
	SessionID         []byte
	CipherSuite       uint16
	CompressionMethod uint8
	ExtensionsLength  uint16
	Extensions        []byte
}

func (h *HandShakeRecord) ParseServerHello() (*ServerHello, error) {
	buffer := bytes.NewBuffer(h.HandShakeMsg)
	serverHello := &ServerHello{}

	// 解析ServerHello消息内容
	if err := binary.Read(buffer, binary.BigEndian, &serverHello.ProtocolVersion); err != nil {
		return nil, err
	}
	if err := binary.Read(buffer, binary.BigEndian, &serverHello.Random); err != nil {
		return nil, err
	}
	if err := binary.Read(buffer, binary.BigEndian, &serverHello.SessionIDLength); err != nil {
		return nil, err
	}
	serverHello.SessionID = make([]byte, serverHello.SessionIDLength)
	if err := binary.Read(buffer, binary.BigEndian, &serverHello.SessionID); err != nil {
		return nil, err
	}
	if err := binary.Read(buffer, binary.BigEndian, &serverHello.CipherSuite); err != nil {
		return nil, err
	}
	if err := binary.Read(buffer, binary.BigEndian, &serverHello.CompressionMethod); err != nil {
		return nil, err
	}

	// 检查是否有扩展字段
	if buffer.Len() > 0 {
		if err := binary.Read(buffer, binary.BigEndian, &serverHello.ExtensionsLength); err != nil {
			return nil, err
		}
		serverHello.Extensions = make([]byte, serverHello.ExtensionsLength)
		if err := binary.Read(buffer, binary.BigEndian, &serverHello.Extensions); err != nil {
			return nil, err
		}
	}
	return serverHello, nil
}

// 解析Certificate
func (h *HandShakeRecord) ParseCertificate() ([]*x509.Certificate, error) {
	// 解析Certificate消息内容
	var certs = make([]*x509.Certificate, 0)
	err := decodeCertificate(h.HandShakeMsg, &certs)
	if err != nil {
		return nil, err
	}
	return certs, nil
}

// ServerHelloDone
func (h *HandShakeRecord) ParseServerHelloDone() ([]byte, error) {
	// 解析Certificate消息内容
	return h.HandShakeMsg, nil
}

// ClientKeyExchange
func (h *HandShakeRecord) ParseClientKeyExchange() ([]byte, error) {
	// 解析Certificate消息内容
	return h.HandShakeMsg[2:], nil
}

// decodeCertificate
func decodeCertificate(data []byte, certs *[]*x509.Certificate) error {
	if len(data) < 4 {
		return errors.New("handshake record too short")
	}
	certLength := bytesToUint32(data[0:3])

	//var cert x509.Certificate
	hl := uint32(3) // header length
	tl := int(hl + certLength)
	if len(data) < tl {
		return errors.New("handle shake length mismatch")
	}
	cert, err := x509.ParseCertificate(data[hl+3 : tl])
	if err != nil {
		return err
	}
	*certs = append(*certs, cert)

	if len(data) == tl {
		return nil
	}
	return decodeCertificate(data[tl:], certs)
}

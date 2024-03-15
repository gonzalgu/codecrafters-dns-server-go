package dnsmessage

import (
	"encoding/binary"
	"fmt"
)

type DNSMessage struct {
	Header   DNSHeader
	Question Question
}

// DNSHeader represents an unpacked DNS message header.
type DNSHeader struct {
	ID      uint16
	QR      byte // Note: Actually 1 bit
	OPCODE  byte // Note: Actually 4 bits
	AA      byte // Note: Actually 1 bit
	TC      byte // Note: Actually 1 bit
	RD      byte // Note: Actually 1 bit
	RA      byte // Note: Actually 1 bit
	Z       byte // Note: Actually 3 bits
	RCODE   byte // Note: Actually 4 bits
	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16
}

type Question struct {
	Labels []string
	Type   uint16
	Class  uint16
}

func UnpackLabels(data []byte) ([]string, int) {
	var res []string
	i := 0
	for data[i] != 0 {
		size := int(data[i])
		res = append(res, string(data[i+1:i+1+size]))
		i += 1 + size
	}
	return res, i + 1
}

func UnpackQuestion(data []byte) (*Question, int) {
	labels, idx := UnpackLabels(data)
	return &Question{
		Labels: labels,
		Type:   binary.BigEndian.Uint16(data[idx : idx+2]),
		Class:  binary.BigEndian.Uint16(data[idx+2 : idx+4]),
	}, idx + 4
}

func (q *Question) Pack() []byte {
	l := 1
	for _, s := range q.Labels {
		l += len(s) + 1
	}
	buffer := make([]byte, l+4)
	i := 0
	for _, s := range q.Labels {
		l := len(s)
		buffer[i] = byte(l)
		i++
		copy(buffer[i:i+l], []byte(s))
		i += l
	}
	buffer[i] = 0x00
	i++
	binary.BigEndian.PutUint16(buffer[i:i+2], q.Type)
	binary.BigEndian.PutUint16(buffer[i+2:i+4], q.Class)
	return buffer
}

// Pack converts the DNSHeader struct into a 12-byte slice in network byte order.
func (h *DNSHeader) Pack() []byte {
	data := make([]byte, 12)
	binary.BigEndian.PutUint16(data[0:2], h.ID)
	data[2] = h.QR<<7 | h.OPCODE<<3 | h.AA<<2 | h.TC<<1 | h.RD
	data[3] = h.RA<<7 | h.Z<<4 | h.RCODE
	binary.BigEndian.PutUint16(data[4:6], h.QDCOUNT)
	binary.BigEndian.PutUint16(data[6:8], h.ANCOUNT)
	binary.BigEndian.PutUint16(data[8:10], h.NSCOUNT)
	binary.BigEndian.PutUint16(data[10:12], h.ARCOUNT)
	return data
}

// UnpackDNSHeader creates a DNSHeader from a 12-byte slice in network byte order.
func UnpackDNSHeader(data []byte) *DNSHeader {
	if len(data) != 12 {
		return nil // or handle error more gracefully
	}
	return &DNSHeader{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		QR:      data[2] >> 7,
		OPCODE:  (data[2] >> 3) & 0x0F,
		AA:      (data[2] >> 2) & 0x01,
		TC:      (data[2] >> 1) & 0x01,
		RD:      data[2] & 0x01,
		RA:      data[3] >> 7,
		Z:       (data[3] >> 4) & 0x07,
		RCODE:   data[3] & 0x0F,
		QDCOUNT: binary.BigEndian.Uint16(data[4:6]),
		ANCOUNT: binary.BigEndian.Uint16(data[6:8]),
		NSCOUNT: binary.BigEndian.Uint16(data[8:10]),
		ARCOUNT: binary.BigEndian.Uint16(data[10:12]),
	}
}

// String returns a string representation of the DNSHeader.
func (h *DNSHeader) String() string {
	return fmt.Sprintf("DNS Header:\n"+
		"ID: %d\n"+
		"QR: %d\n"+
		"OPCODE: %d\n"+
		"AA: %d\n"+
		"TC: %d\n"+
		"RD: %d\n"+
		"RA: %d\n"+
		"Z: %d\n"+
		"RCODE: %d\n"+
		"QDCOUNT: %d\n"+
		"ANCOUNT: %d\n"+
		"NSCOUNT: %d\n"+
		"ARCOUNT: %d\n",
		h.ID, h.QR, h.OPCODE, h.AA, h.TC, h.RD, h.RA, h.Z, h.RCODE,
		h.QDCOUNT, h.ANCOUNT, h.NSCOUNT, h.ARCOUNT)
}

/*
	func (m *DNSMessage) String() string {
		return fmt.Sprintf("DNS Message:\n%s\n", m.Header.String())
	}
*/
func (d *DNSMessage) Pack() []byte {
	return append(d.Header.Pack(), d.Question.Pack()...)
}

func Unpack(data []byte) *DNSMessage {
	hd := UnpackDNSHeader(data[:12])
	q, _ := UnpackQuestion(data[12:])
	return &DNSMessage{
		Header:   *hd,
		Question: *q,
	}
}

func Process(dnsQuery DNSMessage) DNSMessage {
	response := DNSMessage{
		Header: DNSHeader{
			ID:      1234,
			QR:      1,
			OPCODE:  0,
			AA:      0,
			TC:      0,
			RD:      0,
			RA:      0,
			Z:       0,
			RCODE:   0,
			QDCOUNT: 1,
			ANCOUNT: 0,
			NSCOUNT: 0,
			ARCOUNT: 0,
		},
		Question: Question{
			Labels: []string{"codecrafters", "io"},
			Type:   1,
			Class:  1,
		},
	}
	return response
}

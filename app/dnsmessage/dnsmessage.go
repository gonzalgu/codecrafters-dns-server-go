package dnsmessage

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type DNSMessage struct {
	Header   DNSHeader
	Question []Question
	Answer   []Answer
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

type Answer struct {
	RR []RR
}

type RR struct {
	Name     []string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    uint32
}

func (a *Answer) Pack() []byte {
	var buffer bytes.Buffer
	for _, rr := range a.RR {
		buffer.Write(rr.Pack())
	}
	return buffer.Bytes()
}

func UnpackAnswer(data []byte) (*Answer, int) {
	rr, len := UnpackRR(data)
	return &Answer{
		RR: []RR{
			*rr,
		},
	}, len
}

func (rr *RR) Pack() []byte {
	var buffer bytes.Buffer
	for _, s := range rr.Name {
		l := len(s)
		buffer.WriteByte(byte(l))
		for _, c := range s {
			buffer.WriteByte(byte(c))
		}
	}
	buffer.WriteByte(0x00)
	binary.Write(&buffer, binary.BigEndian, rr.Type)
	binary.Write(&buffer, binary.BigEndian, rr.Class)
	binary.Write(&buffer, binary.BigEndian, rr.TTL)
	binary.Write(&buffer, binary.BigEndian, rr.RDLength)
	binary.Write(&buffer, binary.BigEndian, rr.RData)
	return buffer.Bytes()
}

func UnpackRR(data []byte) (*RR, int) {
	labels, idx := UnpackLabels(data)
	return &RR{
		Name:     labels,
		Type:     binary.BigEndian.Uint16(data[idx : idx+2]),
		Class:    binary.BigEndian.Uint16(data[idx+2 : idx+4]),
		TTL:      binary.BigEndian.Uint32(data[idx+4 : idx+8]),
		RDLength: binary.BigEndian.Uint16(data[idx+8 : idx+10]),
		RData:    binary.BigEndian.Uint32(data[idx+10 : idx+14]),
	}, idx + 14
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
	var buffer bytes.Buffer
	for _, s := range q.Labels {
		l := len(s)
		buffer.WriteByte(byte(l))
		for _, c := range s {
			buffer.WriteByte(byte(c))
		}
	}
	buffer.WriteByte(0x00)
	binary.Write(&buffer, binary.BigEndian, q.Type)
	binary.Write(&buffer, binary.BigEndian, q.Class)
	return buffer.Bytes()
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

func (d *DNSMessage) Pack() []byte {
	packed := d.Header.Pack()
	for _, q := range d.Question {
		packed = append(packed, q.Pack()...)
	}
	for _, a := range d.Answer {
		packed = append(packed, a.Pack()...)
	}
	return packed
}

func Unpack(data []byte) *DNSMessage {
	hd := UnpackDNSHeader(data[:12])
	idx := 12
	qs := make([]Question, 0)
	for i := 0; i < int(hd.QDCOUNT); i++ {
		q, len := UnpackQuestion(data[idx:])
		idx += len
		qs = append(qs, *q)
	}
	as := make([]Answer, 0)
	for i := 0; i < int(hd.ANCOUNT); i++ {
		a, len := UnpackAnswer(data[idx:])
		idx += len
		as = append(as, *a)
	}
	return &DNSMessage{
		Header:   *hd,
		Question: qs,
		Answer:   as,
	}
}

func Process(dnsQuery DNSMessage) DNSMessage {
	rcode := 0
	if dnsQuery.Header.OPCODE == 0 {
		rcode = 0
	} else {
		rcode = 4
	}
	header := DNSHeader{
		ID:      dnsQuery.Header.ID,
		QR:      1,
		OPCODE:  dnsQuery.Header.OPCODE,
		AA:      0,
		TC:      0,
		RD:      dnsQuery.Header.RD,
		RA:      0,
		Z:       0,
		RCODE:   byte(rcode),
		QDCOUNT: 1,
		ANCOUNT: 1,
		NSCOUNT: 0,
		ARCOUNT: 0,
	}

	questions := make([]Question, dnsQuery.Header.QDCOUNT)
	answers := make([]Answer, dnsQuery.Header.QDCOUNT)

	for i := 0; i < int(dnsQuery.Header.QDCOUNT); i++ {
		questions[i] = Question{
			Labels: dnsQuery.Question[i].Labels,
			Type:   1,
			Class:  1,
		}
		answers[i] = Answer{
			RR: []RR{
				{
					Name:     dnsQuery.Question[i].Labels,
					Type:     1,
					Class:    1,
					TTL:      60,
					RDLength: 4,
					RData:    binary.BigEndian.Uint32([]byte{0x08, 0x08, 0x08, 0x08}),
				},
			},
		}
	}

	response := DNSMessage{
		Header:   header,
		Question: questions,
		Answer:   answers,
	}
	return response
}

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

func UnpackAnswer(data []byte, offset int) (*Answer, int) {
	rr, len := UnpackRR(data, offset)
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

func UnpackRR(data []byte, offset int) (*RR, int) {
	labels, offset := UnpackLabels(data, offset)
	return &RR{
		Name:     labels,
		Type:     binary.BigEndian.Uint16(data[offset : offset+2]),
		Class:    binary.BigEndian.Uint16(data[offset+2 : offset+4]),
		TTL:      binary.BigEndian.Uint32(data[offset+4 : offset+8]),
		RDLength: binary.BigEndian.Uint16(data[offset+8 : offset+10]),
		RData:    binary.BigEndian.Uint32(data[offset+10 : offset+14]),
	}, offset + 14
}

func UnpackLabels(data []byte, offset int) ([]string, int) {
	var res []string

	for {
		b := data[offset]
		//tmp := b & 0xc0
		if b == 0 {
			//end of sequence
			break
		} else if (b & 0xc0) == 0xc0 {
			//pointer to label
			ptr := b & 0x3F
			offset++
			ptr = (ptr << 7) + data[offset]
			label, _ := UnpackLabels(data, int(ptr))
			res = append(res, label...)
			break
		} else {
			size := int(b)
			res = append(res, string(data[offset+1:offset+1+size]))
			offset += 1 + size
		}
	}
	return res, offset + 1
}

func UnpackQuestion(data []byte, offset int) (*Question, int) {
	labels, offset := UnpackLabels(data, offset)
	return &Question{
		Labels: labels,
		Type:   binary.BigEndian.Uint16(data[offset : offset+2]),
		Class:  binary.BigEndian.Uint16(data[offset+2 : offset+4]),
	}, offset + 4
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
	offset := 0
	hd := UnpackDNSHeader(data[:12])
	offset = 12
	qs := make([]Question, 0)
	for i := 0; i < int(hd.QDCOUNT); i++ {
		q, len := UnpackQuestion(data, offset)
		offset = len
		qs = append(qs, *q)
	}
	as := make([]Answer, 0)
	for i := 0; i < int(hd.ANCOUNT); i++ {
		a, len := UnpackAnswer(data, offset)
		offset = len
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
		QDCOUNT: dnsQuery.Header.QDCOUNT,
		ANCOUNT: dnsQuery.Header.QDCOUNT,
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

func SplitQuery(query DNSMessage) []DNSMessage {
	splittedQueries := make([]DNSMessage, query.Header.QDCOUNT)
	for i := 0; i < int(query.Header.QDCOUNT); i++ {
		header := DNSHeader{
			ID:      query.Header.ID,
			QR:      query.Header.QR,
			OPCODE:  query.Header.OPCODE,
			AA:      query.Header.AA,
			TC:      query.Header.TC,
			RD:      query.Header.RD,
			RA:      query.Header.RA,
			Z:       query.Header.Z,
			RCODE:   query.Header.RCODE,
			QDCOUNT: 1,
			ANCOUNT: 0,
			NSCOUNT: 0,
			ARCOUNT: 0,
		}
		splittedQueries[i] = DNSMessage{
			Header: header,
			Question: []Question{
				query.Question[i],
			},
		}
	}
	return splittedQueries
}

func CombineResponses(responses []DNSMessage) DNSMessage {
	header := responses[0].Header
	header.QDCOUNT = uint16(len(responses))
	header.ANCOUNT = uint16(len(responses))

	dnsmessage := DNSMessage{
		Header:   header,
		Question: make([]Question, len(responses)),
		Answer:   make([]Answer, len(responses)),
	}

	for i := 0; i < len(responses); i++ {
		if responses[i].Header.QDCOUNT == 1 {
			dnsmessage.Question[i] = responses[i].Question[0]
		}
		if responses[i].Header.ANCOUNT == 1 {
			dnsmessage.Answer[i] = responses[i].Answer[0]
		}
	}
	return dnsmessage
}

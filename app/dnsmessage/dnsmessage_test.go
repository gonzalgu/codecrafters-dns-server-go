package dnsmessage

import (
	"fmt"
	"testing"
)

func TestDNSHeaderPackUnpack(t *testing.T) {
	header := DNSHeader{
		ID:      1234,
		QR:      1,
		OPCODE:  0,
		AA:      0,
		TC:      0,
		RD:      0,
		RA:      0,
		Z:       0,
		RCODE:   0,
		QDCOUNT: 0,
		ANCOUNT: 0,
		NSCOUNT: 0,
		ARCOUNT: 0,
	}

	packed := header.Pack()
	unpacked := UnpackDNSHeader(packed)

	fmt.Printf("header: %s\n", &header)
	fmt.Printf("unpacked: %s\n", unpacked)

	if unpacked.ID != header.ID ||
		unpacked.QR != header.QR ||
		unpacked.OPCODE != header.OPCODE ||
		// Add checks for all fields...
		unpacked.ARCOUNT != header.ARCOUNT {
		t.Errorf("Unpacked header does not match original")
	}
}

func TestUnpackLabels(t *testing.T) {
	buffer := []byte{0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01}
	labels, offset := UnpackLabels(buffer, 0)
	fmt.Printf("labels: %v+\n", labels)
	fmt.Printf("idx: %d\n", offset)
	if labels[0] != "google" || labels[1] != "com" || offset != 12 {
		t.Errorf("Error unpacking labels")
	}
}

func TestUpackCompressedLabels(t *testing.T) {
	buffer := []byte{
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x01, byte('F'),
		0x03, byte('I'),
		byte('S'), byte('I'),
		0x04, byte('A'),
		byte('R'), byte('P'),
		byte('A'), 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x03, byte('F'),
		byte('O'), byte('O'),
		0xc0, byte(20),
		0xc0, byte(26),
	}

	//at offset 0 empty
	labels, offset := UnpackLabels(buffer, 0)
	fmt.Printf("labels: %v+\n", labels)
	fmt.Printf("idx: %d\n", offset)

	if len(labels) != 0 {
		t.Errorf("expected empty")
	}

	labels, offset = UnpackLabels(buffer, 20)
	fmt.Printf("labels: %v+\n", labels)
	fmt.Printf("idx: %d\n", offset)

	if len(labels) == 0 {
		t.Errorf("expected non-empty")
	}

	labels, offset = UnpackLabels(buffer, 40)
	fmt.Printf("labels: %v+\n", labels)
	fmt.Printf("idx: %d\n", offset)

	if len(labels) == 0 {
		t.Errorf("expected non-empty")
	}

	labels, offset = UnpackLabels(buffer, 46)
	fmt.Printf("labels: %v+\n", labels)
	fmt.Printf("idx: %d\n", offset)
	if len(labels) == 0 {
		t.Errorf("expected non-empty")
	}
	/*
		if labels[0] != "google" || labels[1] != "com" || offset != 12 {
			t.Errorf("Error unpacking labels")
		}
	*/
}

func TestQuestionPackUnpack(t *testing.T) {
	question := Question{
		Labels: []string{"google", "com"},
		Type:   1,
		Class:  1,
	}

	packed := question.Pack()
	unpacked, l := UnpackQuestion(packed, 0)

	fmt.Printf("question: %v+\n", question)
	fmt.Printf("unpacked: %v+\n", *unpacked)
	fmt.Printf("len: %d\n", l)
	if question.Labels[0] != unpacked.Labels[0] || question.Type != unpacked.Type || question.Class != unpacked.Class || l != 16 {
		t.Errorf("Error unpacking question")
	}
}

func TestMessagePackUnpack(t *testing.T) {
	msg := DNSMessage{
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
			ANCOUNT: 1,
			NSCOUNT: 0,
			ARCOUNT: 0,
		},
		Question: []Question{{
			Labels: []string{"google", "com"},
			Type:   1,
			Class:  1,
		}},
		//Answer: []Answer{},
		Answer: []Answer{{
			RR: []RR{
				{
					Name:     []string{"codecrafters", "io"},
					Type:     1,
					Class:    1,
					TTL:      60,
					RDLength: 4,
					RData:    1234,
				},
			},
		}},
	}
	packed := msg.Pack()
	unpacked := Unpack(packed)
	fmt.Printf("msg: %v+\n", msg)
	fmt.Printf("unpacked: %v+\n", unpacked)
}

func TestRRPackUnpack(t *testing.T) {
	rr := RR{
		Name:     []string{"codecrafters", "io"},
		Type:     1,
		Class:    1,
		TTL:      60,
		RDLength: 4,
		RData:    1234,
	}
	packed := rr.Pack()
	unpacked, _ := UnpackRR(packed, 0)
	fmt.Printf("rr: %v+\n", rr)
	fmt.Printf("unpacked: %v+\n", unpacked)
}

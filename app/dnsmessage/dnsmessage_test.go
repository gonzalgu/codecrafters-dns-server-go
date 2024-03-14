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

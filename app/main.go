package main

import (
	"flag"
	"fmt"
	"os"

	// Uncomment this block to pass the first stage
	"net"

	"github.com/codecrafters-io/dns-server-starter-go/app/dnsmessage"
)

func main() {

	for index, arg := range os.Args {
		fmt.Printf("Arg %d: %s\n", index, arg)
	}

	resolverAddress := flag.String("resolver", "", "The address of the resolver to use")
	flag.Parse()
	if *resolverAddress == "" {
		fmt.Println("please provide a resolver address using --resolver arg")
	}

	//get forwarder
	fmt.Printf("forwarding to: %s\n", *resolverAddress)
	fwd, err := NewForwarder(*resolverAddress)
	if err != nil {
		fmt.Printf("error getting resolver: %v+", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 1024)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		dnsQuery := readQuery(buf[:size])
		fmt.Printf("dnsQuery: %v\n", dnsQuery)

		response, err := process(dnsQuery, fwd)
		if err != nil {
			fmt.Println("error processing request: ", err)
			break
		}
		fmt.Printf("response: %+v\n", response)
		responseBytes := response.Pack()

		_, err = udpConn.WriteToUDP(responseBytes, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
			break
		}
	}
}

func process(dnsQuery *dnsmessage.DNSMessage, fwd *Forwarder) (*dnsmessage.DNSMessage, error) {
	if fwd != nil {
		fmt.Printf("procesing with forwarding: %v+\n", fwd)
		response, err := sendToForwarder(fwd, dnsQuery)
		if err != nil {
			return nil, err
		}
		return response, nil
	} else {
		fmt.Println("default processing.")
		response := dnsmessage.Process(*dnsQuery)
		return &response, nil
	}
}

func readQuery(buffer []byte) *dnsmessage.DNSMessage {
	return dnsmessage.Unpack(buffer)
}

type Forwarder struct {
	UDPAddr *net.UDPAddr
}

func NewForwarder(resolverAddress string) (*Forwarder, error) {
	if resolverAddress == "" {
		return nil, nil
	}
	udpAddr, err := net.ResolveUDPAddr("udp", resolverAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %s", err)
	}
	return &Forwarder{
		UDPAddr: udpAddr,
	}, nil
}

func (fwd *Forwarder) sendQuery(query *dnsmessage.DNSMessage) (*dnsmessage.DNSMessage, error) {
	bytes := query.Pack()
	udpConn, err := net.DialUDP("udp", nil, fwd.UDPAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind to address: %s", err)
	}
	defer udpConn.Close()

	_, err = udpConn.Write(bytes)
	fmt.Printf("sent query %v+ to %v\n", *query, *fwd)
	if err != nil {
		return nil, err
	}

	//read response
	buf := make([]byte, 1024)
	fmt.Printf("reading")
	size, source, err := udpConn.ReadFromUDP(buf)
	if err != nil {
		fmt.Println("Error receiving data:", err)
		return nil, err
	}

	receivedData := string(buf[:size])
	fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

	response := readQuery(buf[:size])
	fmt.Printf("response received: %v+\n", response)
	return response, nil
}

func sendToForwarder(fwd *Forwarder, query *dnsmessage.DNSMessage) (*dnsmessage.DNSMessage, error) {
	requests := dnsmessage.SplitQuery(*query)
	responses := make([]dnsmessage.DNSMessage, len(requests))
	//send each request to resolver
	fmt.Printf("sending %d requests to forwarder.", len(requests))
	for i, request := range requests {
		response, err := fwd.sendQuery(&request)
		if err != nil {
			return nil, fmt.Errorf("error sending request to resolver %v", err)
		}
		responses[i] = *response
	}
	//consolidate all responses into a single response
	consolidated := dnsmessage.CombineResponses(responses)
	return &consolidated, nil

}

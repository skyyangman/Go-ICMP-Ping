package main

import (
	"bytes"
	"flag"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"math"
	"math/rand"
	"net"
	"os"
	"time"
)

const (
	protocolICMP     = 1
	protocolIPv6ICMP = 58
)

// initPing returns a new ping struct pointer
func initPing() (*ping, error) {
	hostname := os.Args[1:][len(os.Args)-2]
	ip, err := net.ResolveIPAddr("ip", hostname)
	if err != nil {
		return nil, err
	}

	var ip4 bool
	if isIPv4(ip.IP) {
		ip4 = true
	} else if isIPv6(ip.IP) {
		ip4 = false
	}

	ip, err = net.ResolveIPAddr("ip", hostname)
	if err != nil {
		fmt.Println(err)
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return &ping{
		ip:       ip,
		hostname: hostname,
		interval: time.Second,
		timeout:  time.Second * 100000,
		id:       r.Intn(math.MaxInt16),
		count:    -1, //-1 for infinity
		ttl:      64,
		network:  "udp",
		ip4:      ip4,
		dataSize: 64,
	}, nil
}

// ping struct contains the fields of a ping activity
type ping struct {
	count       int
	interval    time.Duration
	timeout     time.Duration
	ip          *net.IPAddr // network number
	id          int         // packet id
	hostname    string      // host string name
	packetsRecv int         // number of packets received
	packetsSent int         // number of packets sent
	packetLoss  float64     // percentage of packets lost
	seq         int         // sequence
	network     string      // network type
	ip4         bool        // IP version 4
	ttl         int         // Time To Live of packet
	dataSize    int
}

func isIPv4(ip net.IP) bool {
	return ip.To4() != nil
}

func isIPv6(ip net.IP) bool {
	return len(ip) == net.IPv6len
}

func main() {
	// input validation
	if len(os.Args) == 1 {
		fmt.Println("Please specify an hostname or IP address.")
		return
	}

	p, err := initPing()
	if err != nil {
		fmt.Println(err)
	}

	// specify number of pings
	flag.IntVar(&p.count, "c", -1, "Number of pings requested, default is infinite.")

	// specify an TTL
	flag.IntVar(&p.ttl, "t", 64, "Specify TTL - Time to Live, default is 64")

	// specify data size
	flag.IntVar(&p.dataSize, "s", 64, "Size (in bytes) of the ping packet, default is 64.")

	// specify an interval
	flag.DurationVar(&p.interval, "i", 1, "Time (in second) between ping request, default is 1")

	flag.Parse()

	for i := 0; i < p.count || p.count == -1; i++ {
		var conn *icmp.PacketConn

		if p.ip4 {
			conn, err = icmp.ListenPacket("udp4", "")
			conn.IPv4PacketConn().SetTTL(p.ttl)
			conn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)
		} else {
			conn, err = icmp.ListenPacket("udp6", "")
			conn.IPv6PacketConn().SetHopLimit(p.ttl)
			conn.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true)
		}

		var typ icmp.Type
		if p.ip4 {
			typ = ipv4.ICMPTypeEcho
		} else {
			typ = ipv6.ICMPTypeEchoRequest
		}

		// construct message to be sent
		data := bytes.Repeat([]byte{1}, p.dataSize)
		body := &icmp.Echo{
			ID:   p.id,
			Seq:  p.seq,
			Data: data,
		}
		p.seq++
		msg := &icmp.Message{
			Type: typ,
			Code: 0,
			Body: body,
		}

		msgBytes, err := msg.Marshal(nil)
		if err != nil {
			fmt.Println(err)
			continue
		}

		// timer starts now
		start := time.Now()

		var dst net.Addr = p.ip
		if p.network == "udp" {
			dst = &net.UDPAddr{IP: p.ip.IP, Zone: p.ip.Zone}
		}
		_, err = conn.WriteTo(msgBytes, dst)
		if err != nil {
			fmt.Println(err)
			continue
		}

		if err = conn.SetReadDeadline(time.Now().Add(time.Millisecond * p.timeout)); err != nil {
			fmt.Println(err)
			continue
		}

		// process received datagram OR packet
		var ttl, n int
		bytes := make([]byte, 512)
		if p.ip4 {
			var cm *ipv4.ControlMessage
			n, cm, _, err = conn.IPv4PacketConn().ReadFrom(bytes)
			if cm != nil {
				ttl = cm.TTL
			}
		} else {
			var cm *ipv6.ControlMessage
			n, cm, _, err = conn.IPv6PacketConn().ReadFrom(bytes)
			if cm != nil {
				ttl = cm.HopLimit
			}
		}

		if ttl > p.ttl {
			fmt.Print("Timeout: Time to live exceeded! ")
		}

		// set ICMPv4 or ICMPv6 protocol number
		var proto int
		if p.ip4 {
			proto = protocolICMP
		} else {
			proto = protocolIPv6ICMP
		}

		// parse reply as an ICMP message
		var m *icmp.Message
		if m, err = icmp.ParseMessage(proto, bytes[:n]); err != nil {
			fmt.Println("Error parsing ICMP message")
		}

		// calculate data loss
		lost := 0
		switch packet := m.Body.(type) {
		case *icmp.Echo:
			if p.network == "ip" {
				// Check if reply from same ID
				if packet.ID != p.id {
					fmt.Println("Packet ID do not match.")
				}
			}
			lost += (int)(math.Abs(float64(len(data) - len(packet.Data))))
			min := (int)(math.Min(float64(len(data)), float64(len(packet.Data))))
			for j := 0; j < min; j++ {
				if data[j] != packet.Data[j] {
					lost += 1
				}
			}
		default:
			fmt.Errorf("Invalid ICMP echo reply")
		}

		duration := time.Since(start)

		// output RTT and Data Loss as required
		fmt.Printf("RTT: %.6sms, Data Loss Percentage (in bytes): %d%s(%d/%d)\n", duration, (lost/p.dataSize)*100, "%", lost, p.dataSize)

		// wait for an interval before init another ping request
		time.Sleep(p.interval * time.Second)
	}
}

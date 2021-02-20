package socks5

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
)

const (
	CMD_CONNECT      = 0x01
	CMD_BIND         = 0x02
	CMD_UDP          = 0x03
	ATYPE_IPV4       = 0x01
	ATYPE_DOMAINNAME = 0x03
	ATYPE_IPV6       = 0x04
)

type SocksServer struct {
	tcpAddr *net.TCPAddr
	sockIp  string
	port    int
	udpIp   string //udp associate ip
	udpPort int    // udp associate address
}

func NewSocksServer(socksIp string, port int) *SocksServer {
	socksServer := SocksServer{
		sockIp:  socksIp,
		port:    port,
		udpIp:   socksIp,
		udpPort: port,
	}
	return &socksServer
}

// socks4 socks5 server
func (s *SocksServer) ListenAndServe() {
	go func() {
		udpServer := NewUdpServer(s.udpIp, s.udpPort)
		udpServer.Listen()
	}()
	s.listenSocksServer()
}

func (s *SocksServer) listenSocksServer() error {

	s.tcpAddr, _ = net.ResolveTCPAddr("tcp", s.sockIp+":"+strconv.Itoa(s.port))
	conn, err := net.ListenTCP("tcp", s.tcpAddr)
	if err != nil {
		log.Println("connect error", err)
		return err
	}
	fmt.Println("Listen tcp:" + s.tcpAddr.String())

	for {
		c, err := conn.Accept()
		if err != nil {
			log.Fatal("accept error", err)
			break
		}
		go s.handleConnection(c)

	}
	fmt.Println("go here")
	defer conn.Close()
	return errors.New("socks server stop")
}

func (s *SocksServer) handleConnection(con net.Conn) {
	fmt.Println(con.RemoteAddr().String() + " request for service!")

	ver, err := s.handleVersion(con)
	if err != nil {
		con.Close()
		log.Println(con.RemoteAddr().String()+" error", err)
		return
	}
	if ver == 4 {
		s.handleSocks4(con)
		return
	}
	if ver == 5 {
		err = s.handleAuth(con)
		if err != nil {
			con.Close()
			log.Println(con.RemoteAddr().String()+" error", err)
			return
		}

		err = s.handleRequest(con)
		if err != nil {
			log.Println(con.RemoteAddr().String()+" error", err)
			con.Close()
			return
		}
		return
	}
	//default handle http
	err = s.handleWebProxy(con, ver)
	if err != nil {
		log.Println(con.RemoteAddr().String()+" error", err)
		con.Close()
		return
	}
	return

}

//http CONNECT first char is C
//CONNECT streamline.t-mobile.com:443 HTTP/1.1
func (s *SocksServer) handleVersion(con net.Conn) (byte, error) {

	buf := make([]byte, 1)
	n, err := io.ReadFull(con, buf[:1])
	if n != 1 {
		return 0, errors.New("read header :err" + err.Error())
	}
	ver := buf[0]
	return ver, nil
}

func (s *SocksServer) handleSocks4(con net.Conn) error {

	buf := make([]byte, 256)
	n, err := io.ReadFull(con, buf[:1])
	if n != 1 {
		return errors.New("read header :err" + err.Error())
	}
	cmd := int(buf[0])

	n, err = io.ReadFull(con, buf[:2])
	port := binary.BigEndian.Uint16(buf[:2])

	n, err = io.ReadFull(con, buf[:4])
	addr := net.IP(buf[:4]).String()

	/**
	  IP address 0.0.0.x, with x nonzero,
	an inadmissible destination address and
	thus should never occur if the client can resolve the domain name.)
	Following the NULL byte terminating USERID,
	the client must send the destination domain name
	and terminate it with another NULL byte.
	This is used for both "connect" and "bind" requests.
	*/
	var useDomain = false
	if buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00 && buf[3] != 0x00 {
		useDomain = true
	}

	for {
		n, err = io.ReadFull(con, buf[:1])
		if err != nil {
			return errors.New("read userid error :" + err.Error())
		}
		if buf[0] == 0x00 {
			break
		}
	}
	if useDomain {
		var i = 0
		for {
			n, err = io.ReadFull(con, buf[i:i+1])
			if err != nil {
				return errors.New("read userid error :" + err.Error())
			}
			if buf[i] == 0x00 {
				break
			}
			i++
		}
		addr = string(buf[:i])
	}

	if cmd == CMD_CONNECT {
		return s.handleSock4ConnectCmd(con, addr, port)
	} else {
		return errors.New("not support cmd")
	}
	return nil

}

func (s *SocksServer) handleSock4ConnectCmd(con net.Conn, addr string, port uint16) error {

	destAddrPort := fmt.Sprintf("%s:%d", addr, port)
	dest, err := net.Dial("tcp", destAddrPort)

	/**
	The SOCKS server uses the client information to decide whether the
	request is to be granted. The reply it sends back to the client has
	the same format as the reply for CONNECT request, i.e.,

			+----+----+----+----+----+----+----+----+
			| VN | CD | DSTPORT |      DSTIP        |
			+----+----+----+----+----+----+----+----+
	# of bytes:	   1    1      2              4

		VN
	    reply version, null byte
	REP
	    reply code

	    Byte 	Meaning
	    0x5A 	Request granted
	    0x5B 	Request rejected or failed
	    0x5C 	Request failed because client is not running identd (or not reachable from server)
	    0x5D 	Request failed because client's identd could not confirm the user ID in the request

	DSTPORT
	    destination port, meaningful if granted in BIND, otherwise ignore
	DSTIP
	    destination IP, as above – the ip:port the client should bind to
	*/

	if err != nil {
		con.Write([]byte{0x00, 0x5B, 0x00, 0x00, 0, 0, 0, 0})
		return errors.New("connect dist error :" + err.Error())
	}

	_, err = con.Write([]byte{0x00, 0x5A, 0x00, 0x00, 0, 0, 0, 0})
	if err != nil {
		return errors.New("write  response error:" + err.Error())
	}

	forward := func(src net.Conn, dest net.Conn) {
		defer src.Close()
		defer dest.Close()
		_, err := io.Copy(dest, src)
		if err != nil {
			log.Println(src.RemoteAddr().String(), err)
		}
	}
	fmt.Println(con.RemoteAddr().String() + "-" + dest.LocalAddr().String() + "-" + dest.RemoteAddr().String() + " connect established!")
	go forward(con, dest)
	go forward(dest, con)
	return nil
}

func (s *SocksServer) handleAuth(con net.Conn) error {

	buf := make([]byte, 256)
	n, err := io.ReadFull(con, buf[:1])
	if n != 1 {
		return errors.New("read header :err" + err.Error())
	}
	nmethods := int(buf[0])
	n, err = io.ReadFull(con, buf[:nmethods])
	if n != nmethods {
		return errors.New("read methods error:" + err.Error())
	}

	n, err = con.Write([]byte{0x05, 0x00})
	if n != 2 || err != nil {
		return errors.New("write auth response error:" + err.Error())
	}
	return nil
}

/**

  The SOCKS request is formed as follows:

       +----+-----+-------+------+----------+----------+
       |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
       +----+-----+-------+------+----------+----------+
       | 1  |  1  | X'00' |  1   | Variable |    2     |
       +----+-----+-------+------+----------+----------+

    Where:

         o  VER    protocol version: X'05'
         o  CMD
            o  CONNECT X'01'
            o  BIND X'02'
            o  UDP ASSOCIATE X'03'
         o  RSV    RESERVED
         o  ATYP   address type of following address
            o  IP V4 address: X'01'
            o  DOMAINNAME: X'03'
            o  IP V6 address: X'04'
         o  DST.ADDR       desired destination address
         o  DST.PORT desired destination port in network octet
            order
*/

func (s *SocksServer) handleRequest(con net.Conn) error {

	buf := make([]byte, 256)
	n, err := io.ReadFull(con, buf[:3])
	if n != 3 {
		return errors.New("read connect header :err" + err.Error())
	}
	ver, cmd := int(buf[0]), int(buf[1])
	if ver != 5 {
		return errors.New("bad version")
	}
	addr := ""
	n, err = io.ReadFull(con, buf[:1])
	atype := buf[0]
	if atype == ATYPE_IPV4 {
		n, err = io.ReadFull(con, buf[:4])
		addr = net.IP(buf[:4]).String()
	} else if atype == ATYPE_DOMAINNAME {
		n, err = io.ReadFull(con, buf[:1])
		addrLen := int(buf[0])
		n, err = io.ReadFull(con, buf[:addrLen])
		addr = string(buf[:addrLen])
	} else if atype == ATYPE_IPV6 {
		n, err = io.ReadFull(con, buf[:16])
		addr = string('[') + (net.IP(buf[:16]).String()) + string(']')
		fmt.Println("ipv6:" + addr)
	}

	n, err = io.ReadFull(con, buf[:2])
	port := binary.BigEndian.Uint16(buf[:2])
	if cmd == CMD_CONNECT {
		return s.handleConnectCmd(con, addr, port)
	} else if cmd == CMD_UDP {
		return s.handleUdpCmd(con, addr, port)
	} else {
		return errors.New("not support cmd")
	}
	return nil
}

func (s *SocksServer) handleUdpCmd(con net.Conn, addr string, port uint16) error {

	fmt.Printf("udp ASSOCIATE request %s:%d\n", addr, port)
	/**
	The SOCKS request information is sent by the client as soon as it has
	   established a connection to the SOCKS server, and completed the
	   authentication negotiations.  The server evaluates the request, and
	   returns a reply formed as follows:

	        +----+-----+-------+------+----------+----------+
	        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	        +----+-----+-------+------+----------+----------+
	        | 1  |  1  | X'00' |  1   | Variable |    2     |
	        +----+-----+-------+------+----------+----------+

	     Where:

	          o  VER    protocol version: X'05'
	          o  REP    Reply field:
	             o  X'00' succeeded
	             o  X'01' general SOCKS server failure
	             o  X'02' connection not allowed by ruleset
	             o  X'03' Network unreachable
	             o  X'04' Host unreachable
	             o  X'05' Connection refused
	             o  X'06' TTL expired
	             o  X'07' Command not supported
	             o  X'08' Address type not supported
	             o  X'09' to X'FF' unassigned
	          o  RSV    RESERVED
	          o  ATYP   address type of following address
	             o  IP V4 address: X'01'
	             o  DOMAINNAME: X'03'
	             o  IP V6 address: X'04'
	          o  BND.ADDR       server bound address
	          o  BND.PORT       server bound port in network octet order

	   Fields marked RESERVED (RSV) must be set to X'00'.

	The UDP ASSOCIATE request is used to establish an association within
	   the UDP relay process to handle UDP datagrams.  The DST.ADDR and
	   DST.PORT fields contain the address and port that the client expects
	   to use to send UDP datagrams on for the association.  The server MAY
	   use this information to limit access to the association.  If the
	   client is not in possesion of the information at the time of the UDP
	   ASSOCIATE, the client MUST use a port number and address of all
	   zeros.

	   A UDP association terminates when the TCP connection that the UDP
	   ASSOCIATE request arrived on terminates.

	   In the reply to a UDP ASSOCIATE request, the BND.PORT and BND.ADDR
	   fields indicate the port number/address where the client MUST send
	   UDP request messages to be relayed.
	*/
	udpAddr, _ := net.ResolveIPAddr("ip", s.udpIp)
	hostByte := udpAddr.IP.To4()
	portByte := make([]byte, 2)
	binary.BigEndian.PutUint16(portByte, uint16(s.udpPort))
	buf := append([]byte{0x05, 0x00, 0x00, 0x01}, hostByte...)
	buf = append(buf, portByte...)
	_, err := con.Write(buf)
	//_,err := con.Write([]byte{0x05,0x00,0x00,0x01,0x0a,0x14,0xb,0x71,0x0f,0xa0})
	if err != nil {
		return errors.New("write response error:" + err.Error())
	}

	forward := func(src net.Conn) {
		defer src.Close()
		for {
			_, err := io.ReadFull(src, make([]byte, 100))
			if err != nil {
				break
			}
		}
	}

	go forward(con)
	return nil
}

func (s *SocksServer) handleConnectCmd(con net.Conn, addr string, port uint16) error {

	destAddrPort := fmt.Sprintf("%s:%d", addr, port)
	dest, err := net.Dial("tcp", destAddrPort)

	/**
	The SOCKS request information is sent by the client as soon as it has
	   established a connection to the SOCKS server, and completed the
	   authentication negotiations.  The server evaluates the request, and
	   returns a reply formed as follows:

	        +----+-----+-------+------+----------+----------+
	        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	        +----+-----+-------+------+----------+----------+
	        | 1  |  1  | X'00' |  1   | Variable |    2     |
	        +----+-----+-------+------+----------+----------+

	     Where:

	          o  VER    protocol version: X'05'
	          o  REP    Reply field:
	             o  X'00' succeeded
	             o  X'01' general SOCKS server failure
	             o  X'02' connection not allowed by ruleset
	             o  X'03' Network unreachable
	             o  X'04' Host unreachable
	             o  X'05' Connection refused
	             o  X'06' TTL expired
	             o  X'07' Command not supported
	             o  X'08' Address type not supported
	             o  X'09' to X'FF' unassigned
	          o  RSV    RESERVED
	          o  ATYP   address type of following address
	             o  IP V4 address: X'01'
	             o  DOMAINNAME: X'03'
	             o  IP V6 address: X'04'
	          o  BND.ADDR       server bound address
	          o  BND.PORT       server bound port in network octet order

	   Fields marked RESERVED (RSV) must be set to X'00'.
	*/

	if err != nil {
		con.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return errors.New("connect dist error :" + err.Error())
	}

	_, err = con.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		return errors.New("write  response error:" + err.Error())
	}

	forward := func(src net.Conn, dest net.Conn) {
		defer src.Close()
		defer dest.Close()
		_, err := io.Copy(dest, src)
		if err != nil {
			log.Println(src.RemoteAddr().String(), err)
		}
	}
	fmt.Println(con.RemoteAddr().String() + "-" + dest.LocalAddr().String() + "-" + dest.RemoteAddr().String() + " connect established!")
	go forward(con, dest)
	go forward(dest, con)
	return nil
}

func readString(conn net.Conn, delim byte) (string, error) {

	buf := make([]byte, 1024)
	i := 0
	for {
		current := i
		_, err := conn.Read(buf[current : current+1])
		i++
		if err != nil {
			fmt.Println(err.Error())
			break
		}
		if buf[current] == delim {
			break
		}
		if i == len(buf) {
			break
		}
	}
	return string(buf[:i]), nil
}

func (s *SocksServer) handleWebProxy(con net.Conn, firstc byte) error {

	line, err := readString(con, '\n')
	if err != nil {
		return err
	}
	line = string(firstc) + line
	fmt.Printf(line)
	hostproto := strings.Split(line, " ")

	method := hostproto[0]
	host := hostproto[1]
	proto := hostproto[2]

	if method == "CONNECT" {
		reader := bufio.NewReader(con)
		shp := strings.Split(host, ":")
		addr := shp[0]
		port, _ := strconv.Atoi(shp[1])
		//consume rest header
		for {
			line, err = reader.ReadString('\n')
			if line == "\r\n" {
				break
			}
		}
		return s.handleHTTPConnectMethod(con, addr, uint16(port))
	} else {

		shp := strings.Index(host, "//")
		lasti := strings.Index(host[shp+2:], "/")
		addr := host[shp+2 : lasti+shp+2]
		port := 80
		newline := method + " " + host[lasti+shp+2:] + " " + proto
		return s.handleHTTPProxy(con, addr, uint16(port), newline)
	}
	return nil

}

func (s *SocksServer) handleHTTPConnectMethod(con net.Conn, addr string, port uint16) error {

	destAddrPort := fmt.Sprintf("%s:%d", addr, port)
	dest, err := net.Dial("tcp", destAddrPort)
	/**

	 */
	if err != nil {
		con.Write([]byte("HTTP/1.1 404 Not Found\r\n\r\n"))
		return errors.New("connect dist error :" + err.Error())
	}
	_, err = con.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))

	if err != nil {
		return errors.New("write  response error:" + err.Error())
	}

	forward := func(src net.Conn, dest net.Conn) {
		defer src.Close()
		defer dest.Close()
		_, err := io.Copy(dest, src)
		if err != nil {
			log.Println(src.RemoteAddr().String(), err)
		}
	}
	fmt.Println(con.RemoteAddr().String() + "-" + dest.LocalAddr().String() + "-" + dest.RemoteAddr().String() + " connect established!")
	go forward(con, dest)
	go forward(dest, con)
	return nil
}

// 后续的request line都是全路径，某些服务器可能有问题

func (s *SocksServer) handleHTTPProxy(con net.Conn, addr string, port uint16, line string) error {

	destAddrPort := fmt.Sprintf("%s:%d", addr, port)
	dest, err := net.Dial("tcp", destAddrPort)
	/**
	 */
	if err != nil {
		return errors.New("connect dist error :" + err.Error())
	}
	_, err = dest.Write([]byte(line))
	if err != nil {
		return errors.New("write  response error:" + err.Error())
	}
	forward := func(src net.Conn, dest net.Conn) {
		defer src.Close()
		defer dest.Close()
		_, err := io.Copy(dest, src)
		if err != nil {
			log.Println(src.RemoteAddr().String(), err)
		}
	}
	fmt.Println(con.RemoteAddr().String() + "-" + dest.LocalAddr().String() + "-" + dest.RemoteAddr().String() + " connect established!")
	go forward(con, dest)
	go forward(dest, con)
	return nil
}

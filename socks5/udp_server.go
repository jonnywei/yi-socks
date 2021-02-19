package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"
)


type UdpServer struct {
	udpAddr *net.UDPAddr
	udpIp   string //udp associate ip
	udpPort int // udp associate address
	serverConn *net.UDPConn
	srcUdpMap SrcUdpMap

}


func NewUdpServer(udpIp string, port int) *UdpServer {

	tcpLocal := UdpServer{
		udpIp: udpIp,
		udpPort: port,
		srcUdpMap: SrcUdpMap{
			associated: make(map[string] *SrcUdpInfo),
		},
	}
	return &tcpLocal

}


func (u * UdpServer) Listen() error {

	u.udpAddr, _ = net.ResolveUDPAddr("udp", u.udpIp +":"+ strconv.Itoa(u.udpPort))
	conn,err := net.ListenUDP("udp", u.udpAddr)
	if err != nil {
		log.Println("connect error",err)
		return errors.New("udp listen error")
	}
	fmt.Println("Listen udp:"+u.udpIp+":"+ strconv.Itoa(u.udpPort))
	u.serverConn = conn
	go u.timeout()
	for{
		var data = make([]byte, 8192)
		n, srcAddr, err := conn.ReadFromUDP(data)
		if err != nil {
			log.Println("READ error", err)
			continue
		}
		if n <= 0 {
			continue
		}
		fmt.Printf("[%v]:", srcAddr)
		go u.handleUdpPacket(srcAddr,data[:n])
	}
	fmt.Println("udp server close")
	defer conn.Close()
	return nil
}

func  (u * UdpServer) timeout()  {
	tick := time.Tick(time.Second*100)
	for{
		select {
			case <-tick:
			 	log.Println("tick tick")
				u.srcUdpMap.timeout()
			}
	}

}
/**
     +----+------+------+----------+----------+----------+
      |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
      +----+------+------+----------+----------+----------+
      | 2  |  1   |  1   | Variable |    2     | Variable |
      +----+------+------+----------+----------+----------+

     The fields in the UDP request header are:

          o  RSV  Reserved X'0000'
          o  FRAG    Current fragment number
          o  ATYP    address type of following addresses:
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  DST.ADDR       desired destination address
          o  DST.PORT       desired destination port
          o  DATA     user data
 */

func  (u * UdpServer) handleUdpPacket(srcAddr *net.UDPAddr ,message []byte){
	fmt.Println(srcAddr.String() + " send udp package!")
	length := len(message)
	index := 3
	if length < index {
		log.Println("error package")
		return
	}
 	if message[0] != 0x00 && message[1] != 0x00 {
		log.Println("rev failed not 0x0000")
		return
	}
 	if message[2] != 0x00 {
		log.Println("FRAG  not support")
		return
	}
	atype := message[3]
	index = 4
	var addr  string = ""
	if atype == ATYPE_IPV4{
		index += 4
		addr =  net.IP(message[index-4:index]).String()
	}else if atype == ATYPE_DOMAINNAME{
		addrLen := int(message[index])
		index += 1
		addr = string(message[index:index+addrLen])
		index += addrLen
	}else if atype ==ATYPE_IPV6 {
		addr = net.IP(message[index:index+16]).String()
		index += 16
	}
	port := binary.BigEndian.Uint16(message[index:index+2])
	index += 2
	data := message[index:]
	originHeader := message[0:index]
	u.handleUdpPacket2(srcAddr,addr,port, data,originHeader)


}



func  (u * UdpServer) handleUdpPacket2(srcAddr *net.UDPAddr , dstAddr string, port uint16 ,message []byte ,originHeader []byte){

	srcUdpInfo := u.srcUdpMap.get(srcAddr)
	laddr := srcUdpInfo.localAddr
	var destAddr *net.UDPAddr
	ua := dstAddr +":"+ strconv.Itoa(int(port))
	remoteConn := srcUdpInfo.getRemoteConn(ua)
	if remoteConn == nil {
		destAddr,_ = net.ResolveUDPAddr("udp",ua)
		udpCon,err := net.DialUDP("udp",laddr,destAddr)
		if err != nil {
			log.Println("error connect " +dstAddr)
			return
		}
		remoteConn = udpCon
		srcUdpInfo.addRemoteConn(ua,remoteConn)
		if laddr == nil {
			srcUdpInfo.setLocalAddr( udpCon.LocalAddr().(*net.UDPAddr))
		}
		go u.handleRemoteRead(srcAddr, udpCon, originHeader ,ua, srcUdpInfo)
	}
	_,err := remoteConn.Write(message)
	if err != nil {
		srcUdpInfo.deleteRemoteConn(ua)
		return
	}
	srcUdpInfo.active()
}



func  (u * UdpServer) handleRemoteRead(srcAddr *net.UDPAddr ,  udpCon *net.UDPConn,
			originHeader []byte ,key string , info *SrcUdpInfo){
	var b [65507]byte
	for {
		udpCon.SetReadDeadline( time.Now().Add(time.Duration(time.Second * 100)))
		n, err :=udpCon.Read(b[:])
		if err != nil {
			log.Println("udp read error==========", err)
			break
		}
		info.active()
		buf := append(originHeader, b[:n]...)
		u.serverConn.WriteToUDP(buf,srcAddr)
	}

	info.deleteRemoteConn(key)

}

type SrcUdpMap struct {
	associated map[string] *SrcUdpInfo // src string->src addr
}



func  (u * SrcUdpMap) get(srcAddr *net.UDPAddr ) *SrcUdpInfo{
	src := srcAddr.String()
	if u.associated[src] != nil {
		return u.associated[src]
	}
	r := &SrcUdpInfo{
		srcAddr: srcAddr,
		lastActiveTime:time.Now(),
		localDestCon: make( map[string] *net.UDPConn),
	}
	return r
}


func  (u * SrcUdpMap) delete(srcAddr *net.UDPAddr ) {
	src := srcAddr.String()
	delete(u.associated, src)
}

func  (u * SrcUdpMap) timeout( )  {
	 for k,v := range  u.associated {
	 	if v.lastActiveTime.Add(time.Second*100).Before(time.Now()){
			delete(u.associated, k)
			v.Destroy()
			log.Println("delete" +k)
		}
	 }
}



type SrcUdpInfo struct {
	srcAddr * net.UDPAddr
	localAddr * net.UDPAddr
	lastActiveTime   time.Time
	localDestCon map[string] *net.UDPConn //  dst -> conn
}



func  (u * SrcUdpInfo) setLocalAddr(localAddr *net.UDPAddr  ){
	u.localAddr = localAddr
	u.lastActiveTime = time.Now()

}

func  (u * SrcUdpInfo) active(  )  {
	u.lastActiveTime = time.Now()
}


func  (u * SrcUdpInfo) deleteRemoteConn(remoteAddr string )  {
	if c,ok := u.localDestCon[ remoteAddr]; ok {
		c.Close()
		delete(u.localDestCon, remoteAddr)
	}
}



func  (u * SrcUdpInfo) addRemoteConn(remoteAddr string , con *net.UDPConn )  {
	 u.localDestCon[ remoteAddr] = con
}

func  (u * SrcUdpInfo) getRemoteConn(remoteAddr string ) *net.UDPConn {
	if c,ok := u.localDestCon[ remoteAddr]; ok {
		return c
	}
	return nil
}

func  (u * SrcUdpInfo) Destroy() {
	for _,v := range  u.localDestCon {
		v.Close()
	}
}

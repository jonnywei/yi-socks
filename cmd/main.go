package main

import (
	"flag"
	"github.com/jonnywei/yi-socks/socks5"
)

func main() {

	host := *flag.String("host", "localhost", "listen host")
	port := *flag.Int("port", 1030, "listen port")
	server := socks5.NewSocksServer(host, port)
	server.ListenAndServe()
}

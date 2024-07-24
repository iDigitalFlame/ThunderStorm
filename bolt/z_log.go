//go:build log
// +build log

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

package bolt

import (
	"os"

	"github.com/PurpleSec/logx"
	"github.com/iDigitalFlame/xmt/util"
)

var logger = initLog()

func initLog() logx.Log {
	f, err := logx.File(os.TempDir()+string(os.PathSeparator)+"log-"+util.Uitoa(uint64(os.Getpid()))+".log", logx.Trace)
	if err != nil {
		return logx.Console(logx.Trace)
	}
	return logx.Multiple(f, logx.Console(logx.Trace))
}

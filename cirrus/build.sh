#!/usr/bin/bash
# Copyright (C) 2020 - 2023 iDigitalFlame
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

output="cirrus"
buildroot="cmd/cirrus.go"

if [ $# -ge 1 ]; then
    output="$1"
    if [ -d "$(pwd)/cirrus" ]; then
        buildroot="cirrus/cmd/cirrus.go"
    fi
else
    if [ -d "$(pwd)/cirrus" ]; then
        output="$(pwd)/bin/cirrus"
        buildroot="cirrus/cmd/cirrus.go"
    else
        if [ -f "$(pwd)/server.go" ]; then
            output="$(pwd)/../bin/cirrus"
        fi
    fi
fi

printf "Building...\n"
go build -trimpath -buildvcs=false -ldflags "-s -w -X 'github.com/iDigitalFlame/ThunderStorm/cirrus.version=$(date +%F)_$(git rev-parse --short HEAD 2> /dev/null || echo "non-git")'" -o "$output" $buildroot

which upx &> /dev/null
if [ $? -eq 0 ] && [ -f "$output" ]; then
    upx --compress-exports=1 --strip-relocs=1 --compress-icons=2 --best --no-backup -9 "$output"
fi

printf "Done!\n"

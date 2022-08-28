#!/usr/bin/bash
# Copyright (C) 2020 - 2022 iDigitalFlame
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

echo "Installing ThunderStorm Dependencies..."
pacman -S python make cmake python-websocket-client python-requests go gcc openssl upx mingw-w64-binutils mingw-w64-crt mingw-w64-gcc mingw-w64-headers mingw-w64-winpthreads --noconfirm

echo "Building osslsigncode..."
git clone https://github.com/mtrojnar/osslsigncode "/tmp/osslsigncode"
cd "/tmp/osslsigncode"
mkdir "build"
cd "build"
cmake -S ..
cmake --build .
cmake --install .
rm -rf "/tmp/osslsigncode"

echo "Done!"

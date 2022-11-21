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

echo "Installing ThunderStorm Dependencies.."
apt-get install -y python3 python3-websocket python3-requests golang gcc openssl osslsigncode upx binutils-mingw-w64 gcc-mingw-w64-x86-64-win32-runtime gcc-mingw-w64 gcc-mingw-w64-base gcc-mingw-w64-i686 mingw-w64 mingw-w64-tools

echo "Done!"

#!/usr/bin/python3
# Copyright (C) 2020 - 2023 iDigitalFlame
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

EMPTY = list()

MENU_MAIN = 0
MENU_BOLTS = 1
MENU_BOLT = 2
MENU_BOLT_ALL = 3
MENU_PROFILES = 4
MENU_PROFILE = 5
MENU_LISTENERS = 6
MENU_LISTENER = 7
MENU_SCRIPTS = 8
MENU_SCRIPT = 9
MENU_PACKETS = 10

MENU_INTRO = """Welcome to the Doppler  interface. Use "help" to display the command guide.
Happy hacking!"""

HELP_MAIN = """Welcome to the Doppler CLI!

This is the Main menu, it can be reached from any menu with the "menu" command.
All menus will eventually back into this one.

To exit from Doppler, CTRL-D can be used to exit from any menu, while CTRL-C can
be used to go back (Except when the command line is NOT empty, it will instead
clear the line of any text). Double tapping CTRL-C on the Main menu will also exit
Doppler.

Most Doppler commands can be used with tab-based autocomplete can will automatically
fetch any relevant results from Cirrus.

From this menu, the following options are available:

bolt <BoltID>
  This command will put you in direct control of the Bolt with the matching ID
  value. The special value "all" can be used to put yourself in control of ALL
  Bolts simultaneously. Supplying an additional argument to "all" can specify a
  filter match to shrink the target of the "all" command.

  If the BoltID is empty, this will take you to the Bolts menu.

bolts
  Take you to the Bolts menu.

script <script>
  Enters the interactive scripting interface. This can be used to add/edit
  commands and options of the targeted script.

    If the Script name is empty, this will take you to the Scripts menu.

scripts
  Take you to the Scripts menu.

profile <profile>
  Take you to the Profile-specific menu, which has all the options of the
  Profiles menu, but is targeted to the specific Profile.

  If the Profile name is empty, this will take you to the Profiles menu.

profiles
  Take you to the Profiles menu.

listener <listener>
  Take you to the Listeners-specific menu, which has all the options of the
  Listeners menu, but is targeted to the specific Listener.

  If the Listener name is empty, this will take you to the Listeners menu.

listeners
  Take you to the Listeners menu.

jobs
  List all cached Jobs.

job <BoltID>
  List all cached Jobs for the specific BoltID

job <BoltID> <JobID>
  Retrieve the cached Job output from the specified BoltID and JobID combo.
"""
HELP_MAIN_LS = """bolt
bolts
script
scripts
profile
profiles
listener
listeners
job
jobs
"""
HELP_BOLT_ALL = """This is the ALL Bolts shell.
Each command will be ran on each Bolt (or every bolt in the supplied filter).

Use the "display" and "nodisplay" commands to change output control of commands
completed.

Note that commands that specify an output file (download, screenshot, procdump)
will ignore the output file argument and will use a generated one instead.
"""
HELP_PIPE = '[+] Using runtime Pipe value "{pipe}". Use the "-z/--no-auto" argument to disable this action.'
HELP_DATA = """What are Data Values and Data Specification Identifiers?

Data Values (usually identified by "data") are a method of describing a resource
so it can be parsed properly. Data can come in the form of:

- Strings
- Raw Bytes
- Raw Strings (Not Escaped)
- Base64 Encoded Strings
- Local File Paths
- Remote File Paths

Each of these options might be able to be the source of data used in a
particular command.

By default, each command that uses a Data Value will attempt to automatically
determine the type of data described. Many times this comes down to Strings
and File Paths and some commands will attempt to autodetect Base64 strings.
In order to explicitly tell the command what the data type is, we can use
Data Specification Identifiers to assist.

Many commands may take multiple Data Value types in order to augment their
runtime.

Data Specification Identifiers are a type declariation added to the beginning
of a string to indicate what type it represents.

There are two ways to use Data Specification Identifiers:

- <type>$<data>
- <type>"<data>"

The "type" value is a single character that indicates the type. Here are the
type indicators supported:

- r Raw Strings or Raw Bytes
    Data will be DIRECTLY interpreted as it's explicit form, meaning that
    newlines "\\n" and other control chars DO NOT need to be escaped and will
    act like they were un-escaped. This indication also can be used with the
    "b" indicator interchangeably.
- b Raw Bytes
    Data will be DIRECTLY interpreted as a sequence of bytes. You do not need
    to escape any values and may also use hex codes to signify other data
    values, such as \\xFF and \\x40.
- x Remote File Path
    Data will be DIRECTLY interpreted as a raw REMOTE (on client) path. This
    path will NOT be parsed and instead will be expanded on the client side.
- p Local File Path
    Data will be DIRECTLY interpreted as a raw LOCAL path. This will cause any
    environment variables to be resolved and will result in an error if it
    does not exist.
- e Base64 Encoded String
    Data will be DIRECTLY interpreted as a Base64 encoded string value. It will
    be decoded directly into bytes. This will result in an error if the Base64
    encoding is invalid or incorrect.

As long as the Data Value begins with one of these characters and is either
surrounded in double quotes "" or has a single dollar sign $ after the type
character, it will be evaluated.

Some Examples:
    r"Hello\\nWorld!"
    - Raw String, this will result in:

    Hello
    World!

    e"c3VwZXJzZWNyZXQK"
    - Base64 Encoded String, this will result in:

    supersecret
    (Note the newline at the end).

    b$\\x41\\x42\\x43\\x44\\x45\\x46
    - Raw Bytes, this will result in:

    ABCDEF
"""
HELP_STRVAL = """"""
HELP_SCRIPT = """This is the interactive scripting interface.

Any commands entered here will ONLY be checked for valid parameters and will be
written to the script "{script}".

These will only be executed ONCE the script is ran on a target (as a connection
script or using the "script" command).

Some operations are not available in scripts and any "output" or "destination"
arguments will be omitted and instead randomly generated.

The "undo", "rollback" and "history" commands can be used to view command history
or undo any entries."""

HELP_TEXT = [
    HELP_MAIN,
    "Bolts",
    None,
    None,
    "Profiles",
    "Profile",
    "Listeners",
    "Listener",
]

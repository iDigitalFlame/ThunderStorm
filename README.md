# The ThunderStorm Project

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Latest](https://img.shields.io/github/v/tag/iDigitalFlame/ThunderStorm)](https://github.com/iDigitalFlame/ThunderStorm/releases)

![cirrus](icons/cirrus.png) ![doppler](icons/doppler.png) ![bolt](icons/bolt.png) ![stormfront](icons/stormfront.png) ![jetstream](icons/jetstream.png) ![flurry](icons/flurry.png) ![cloudseed](icons/cloudseed.png)

---

Golang Full C2 Solution using [XMT](https://github.com/iDigitalFlame/xmt)

ThunderStorm is made up of multiple components that work together.

[Documentation repository](docs) is live with new stuff, including:

- The [Quickstart Guide](docs/Quickstart.md)!
- [Bolt Console Command Line Reference](docs/Commands.md) guide.
- [Data Identifiers Reference](docs/Identifiers.md) guide.

## ![cirrus](icons/cirrus.png) Cirrus

*I smell a storm comming*

Cirrus is a ReST cradle for XMT and acts as the primary "teamserver". This can
be used to control and task Bolts (implants).

Cirrus will automatically capture Jobs and new Bolts and has a websocket interface
that can be used to get quick up-to-date information on what's happening.

__ReST documentation is in progress (I swear!)__

## ![bolt](icons/bolt.png) Bolt

*Sometimes lighting does strike twice*

A Bolt is a basic implant that can be used on any client device. Bolts can be
built in multiple modes and will initially talk to the C2 with whatever their
built-in Profile is.

Bolts can be customized to run as services/daemons or as DLLs.

## ![jetstream](icons/jetstream.png) JetStream

*Fly Forward, Fast*

JetStream is a compact, complex Bolt builder engine. JetStream is able to create
new Bolts for many different platforms (including Windows DLLs) and can obfuscate,
encrypt, sign and pack binaries easily.

## ![cloudseed](icons/cloudseed.png) CloudSeed

*Let it Pour*

CloudSeed complements JetStream and is able to build Bolts and Flurries in batches.
Using JetStream, CloudSeed can build hundreds of instances ready to be deployed.

It's __OUR__ answer to Defense-in-Depth.

## ![flurry](icons/flurry.png) Flurry

*Just layer it on*

Flurry (old name Launcher) taps into the Guardian function of XMT and can automatically
resurrect a killed or crashed Bolt in a dirrent process. These rely on a configured Guardian
type and a list of stored filesystem paths (or URLS!) to get a Bolt from.

## ![doppler](icons/doppler.png) Doppler

*You gotta find the eye of the Storm to know where the action is*

Doppler is a Python frontend CLI that can be used to interact with Cirrus. Doppler
supports multiple users at once (it can be ran multiple times) and uses the Cirrus
websocket to get real time data on Jobs and Bolts.

The layout of how commands works is similar to the PowerShell Empire format. (Except
exiting the shell doesn't kill the server). Doppler will automatically manage
filepaths for you (for downloads, uploads, shellcode) and can manage multiple Bolts

Doppler can take command line arguments, environment variables or event a config file!

The layout of the config file with the matching env and arguments is below:

```json
{
    "cirrus": "http://localhost:7777", // env:DOPPLER_HOST args:[-a, --api]
    "cirrus_password": "<password>", //env:DOPPLER_PW args:[-p, --password]
    "default_exec": true, // env:DOPPLER_NO_EMPTY args:[-N, ==no-empty]
    "default_asm": "<path_to_asm_file>", // env:DOPPLER_ASM args:[-A, --as,]
    "default_dll": "<path_to_dll_file>", // env:DOPPLER_DLL args:[-D, --dll]
    "default_pipe": "<migrate_spawn_pipe_name>" // env:DOPPLER_PIPE args:[-P, --pipe]
}
```

Actual JSON config file:

```json
{
    "cirrus": "http://localhost:7777",
    "cirrus_password": "<password>",
    "default_exec": true,
    "default_asm": "<path_to_asm_file>",
    "default_dll": "<path_to_dll_file>",
    "default_pipe": "<migrate_spawn_pipe_name>"
}
```

## TODOs:

__Updated 11/18/22__

- Write Cirrus API documentation

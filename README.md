# ThunderStorm

Golang Full C2 Solution using [XMT](https://github.com/iDigitalFlame/xmt)

ThunderStorm is made up of multiple components that work together.

## Cirrus

Cirrus is a ReST cradle for XMT and acts as the primary "teamserver". This can
be used to control and task Bolts (implants).

Cirrus will automatically capture Jobs and new Bolts and has a websocket interface
that can be used to get quick up-to-date information on what's happening.

__ReST documentation is in progress (I swear!)__

## Bolt

A Bolt is a basic implant that can be used on any client device. Bolts can be
built in multiple modes and will initially talk to the C2 with whatever their
built-in Profile is.

Bolts can be customized to run as services/daemons or as DLLs.

## Launcher (Need a better name for this)

Launchers tap into the Guardian function of XMT and can automatically resurrect a
killed or crashed Bolt in a dirrent process. These rely on a configured Guardian
type and a list of stored filesystem paths (or URLS!) to get a Bolt from.

## Doppler

Doppler is a Python frontend CLI that can be used to interact with Cirrus. Doppler
supports multiple users at once (it can be ran multiple times) and uses the Cirrus
websocket to get real time data on Jobs and Bolts.

The layout of how commands works is similar to the PowerShell Empire format. (
Except exiting the shell doesn't kill the server). Doppler will automaticall manage
filepaths for you (for downloads, uploads, shellcode) and can manage multiple Bolts
at once (WIP!).

**
Currently the Profile Builder (located at doppler/include/config.py) is not built
into the menu, it will be soon!
**

__Building and running instructsions will come soon!__

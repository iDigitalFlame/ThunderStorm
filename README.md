# The ThunderStorm Project

||||||

Golang Full C2 Solution using [XMT](https://github.com/iDigitalFlame/xmt)

ThunderStorm is made up of multiple components that work together.

##  Cirrus

*I smell a storm comming*

Cirrus is a ReST cradle for XMT and acts as the primary "teamserver". This can
be used to control and task Bolts (implants).

Cirrus will automatically capture Jobs and new Bolts and has a websocket interface
that can be used to get quick up-to-date information on what's happening.

__ReST documentation is in progress (I swear!)__

##  Bolt

*Sometimes lighting does strike twice*

A Bolt is a basic implant that can be used on any client device. Bolts can be
built in multiple modes and will initially talk to the C2 with whatever their
built-in Profile is.

Bolts can be customized to run as services/daemons or as DLLs.

##  JetStream

*Fly Forward, Fast*

JetStream is a compact, complex Bolt builder engine. JetStream is able to create
new Bolts for many different platforms (including Windows DLLs) and can obfuscate,
encrypt, sign and pack binaries easily.

##  CloudSeed

*Let it Pour*

CloudSeed complements JetStream and is able to build Bolts and Flurries in batches.
Using JetStream, CloudSeed can build hundreds of instances ready to be deployed.

It's __OUR__ answer to Defense-in-Depth.

##  Flurry

*Just layer it on*

Flurry (old name Launcher) taps into the Guardian function of XMT and can automatically
resurrect a killed or crashed Bolt in a dirrent process. These rely on a configured Guardian
type and a list of stored filesystem paths (or URLS!) to get a Bolt from.

##  Doppler

*You gotta find the eye of the Storm to know where the action is*

Doppler is a Python frontend CLI that can be used to interact with Cirrus. Doppler
supports multiple users at once (it can be ran multiple times) and uses the Cirrus
websocket to get real time data on Jobs and Bolts.

The layout of how commands works is similar to the PowerShell Empire format. (Except
exiting the shell doesn't kill the server). Doppler will automatically manage
filepaths for you (for downloads, uploads, shellcode) and can manage multiple Bolts

**
Currently the Profile Builder (located at doppler/include/config.py) is not built
into the menu, it will be soon!
**

__Building and running instructsions will come soon!__

TODO:

- Cirrus: Make scripts save to disk and load only when needed.
  - Currently scripts are only in memory.

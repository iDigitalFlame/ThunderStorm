#!/usr/bin/python3

from time import sleep
from base64 import b64decode
from include.cirrus import Api, CirrusError


a = Api("http://localhost:7771", "password")


for p in a.packets().keys():
    r = a.packet(p)
    print(p, b64decode(r["data"]))


# while True:
#    print("doing prune..")
#    for i in a.sessions():
#        print("Shutting down", i["id"], i["device"]["pid"])
#        print(a.session_remove(i["id"], True))
#    sleep(20)

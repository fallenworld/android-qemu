#!/usr/bin/env python

DEBUG_PORT = 45678

import socket
import time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', DEBUG_PORT))
s.send("DEBUG CONNECT\0")
print "Waiting for log message"
while 1:
    data = s.recv(1024)
    if not data: continue
    print data,
s.close()

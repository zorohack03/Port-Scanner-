#!/bin/python

import sys
import socket 
from datetime import datetime 

if len(sys.argv) == 2:
    target = socket.gethostbyname(sys.argv[1])
else:
     print("invalid amount of arguement ")
     print("syntax: python3 scanner.py <ip>")

print("scanning Target:"+target)
print("time started:"+str(datetime.now()))

try:
      for port in range(1,65535):
           s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
           socket.setdefaulttimeout(1)
           result=s.connect_ex((target,port))
           if result == 0:
               print("port {} is open ".format(port))
           s.close()

except KeyboardInterrupt:
       print("\nExiting program")
       sys.exit()
       
except socket.gaierror:
       print("hostname could not be resolved ")
       sys.exit()
      
except socket.error:
       print("couldn't connect to server ")
       sys.exit()
       

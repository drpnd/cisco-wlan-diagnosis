#!/usr/bin/env python3

import cgi
import os

args = cgi.FieldStorage()

## Function
try:
    f = args['f']
except:
    f = 'default'


print("Content-type: text/plain\n")
if "REMOTE_ADDR" in os.environ:
    print(os.environ["REMOTE_ADDR"])
else:
    print("")

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from module import globals
from module.time import now
from module.color import color

def dismap(line):
    if "dismap" in line:
        print(now.timed(de=0) + color.yel_info() + color.green(" The file is dismap Identification results"))
        globals.set_value("DISMAP", "true")
        return "######"
    elif "######" in line:
        return "######"
    if globals.get_value("DISMAP") == "true":
        try:
            search = re.findall("[{] (.*?) [}]", line)
            return search[0]
        except:
            return
    else:
        return line

def dismap_getwebapps(line):
    if (line.find("[+]") == 0):
        try:
            search = re.findall("(.*?) [{] ", line)
            return search[0]
        except:
            return
    else:
     return

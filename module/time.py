#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import time
from datetime import datetime
from module.color import color


class Timed:
    @staticmethod
    def timed(de):
        get_time = datetime.now()
        time.sleep(de)
        timed = color.cyan("["+str(get_time)[11:19]+"] ")
        return timed
    @staticmethod
    def timed_line(de):
        get_time = datetime.now()
        time.sleep(de)
        timed = color.cyan("["+str(get_time)[11:19]+"] ")
        return timed
    @staticmethod
    def no_color_timed(de):
        get_time = datetime.now()
        time.sleep(de)
        no_color_timed = "["+str(get_time)[11:19]+"] "
        return no_color_timed


now = Timed()

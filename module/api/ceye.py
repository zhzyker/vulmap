#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests
from module import globals
from module.color import color
from module.time import now


def ceye():
    timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
    headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
    ceye_domain = globals.get_value("ceye_domain")
    ceye_token = globals.get_value("ceye_token")
    ceye_token = globals.get_value("ceye_token")
    api_url = "http://api.ceye.io/v1/records?type=dns&token=" + ceye_token
    res = requests.get(api_url, headers=headers, timeout=timeout, verify=False)
    if res.status_code != 200:
        print(now.timed(de=0) + color.red_warn() + color.red(" Ceye.io: " + res.text))
    return res.text

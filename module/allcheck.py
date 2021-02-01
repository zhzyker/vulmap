#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import requests
import platform
from module.color import color
from module.time import now
from module import globals


def version_check():
    version = globals.get_value("VULMAP")  # 获取全局变量VULMAP版本号
    timeout = globals.get_value("TIMEOUT")  # 获取全局变量TIMEOUT
    headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
    github_ver_url = "https://github.com/zhzyker/vulmap/blob/main/version"
    now_warn = now.timed(de=0) + color.red_warn()
    try:
        github_ver_request = requests.get(url=github_ver_url, headers=headers, timeout=timeout)
        version_res = r'blob-code blob-code-inner js-file-line">(.*)</td>'
        github_ver = re.findall(version_res, github_ver_request.text, re.S | re.M)[0]
        if version == github_ver:
            print(now.timed(de=0) + color.yel_info() + color.yellow(" Currently the latest version: " + version))
        elif version < github_ver:
            print(now_warn + color.red(" The current version is: " + version + ", Latest version: " + github_ver))
            print(now_warn + color.red(" Go to github https://github.com/zhzyker/vulmap update"))
        else:
            print(now_warn + color.red(" Unknown version: " + version))
    except requests.exceptions.ConnectionError:
        print(now_warn + color.red(" The current version is: " + version + ", Version check filed"))
    except requests.exceptions.Timeout:
        print(now_warn + color.red(" The current version is: " + version + ", Version check filed"))


def os_check():
    if platform.system().lower() == 'windows':
        return "windows"
    elif platform.system().lower() == 'linux':
        return "linux"
    else:
        return "other"


def url_check(url):
    try:
        if url[-1] == "/":
            url = url[:-1]
            return url
        if r"http://" not in url and r"https://" not in url:
            if r"443" in url:
                url = "https://" + url
                return url
            else:
                url = "http://" + url
                return url
        else:
            return url
    except AttributeError:
        pass


def survival_check(url):
    try:
        timeout = globals.get_value("TIMEOUT")  # 获取全局变量TIMEOUT
        headers = globals.get_value("HEADERS")
        target = url_check(url)
        requests.get(target, timeout=timeout, headers=headers, verify=False)
        return "s"
    except requests.exceptions.ConnectionError:
        return "f"
    except requests.exceptions.Timeout:
        return "f"

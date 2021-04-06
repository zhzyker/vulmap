#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import socket
import random
import platform
from module import globals
from module.time import now
from module.color import color
from thirdparty import requests
from urllib.parse import urlparse


def version_check():
    n = random.choice(range(10))
    if n <= 1:
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
                print(now_warn + color.red(" Internal beta version: " + version))
        except requests.exceptions.ConnectionError:
            print(now_warn + color.red(" The current version is: " + version + ", Version check failed"))
        except requests.exceptions.Timeout:
            print(now_warn + color.red(" The current version is: " + version + ", Version check failed"))


def os_check():
    if platform.system().lower() == 'windows':
        return "windows"
    elif platform.system().lower() == 'linux':
        return "linux"
    else:
        return "other"


def url_check(url):
    try:
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
        return url


def survival_check(url):
    if globals.get_value("CHECK") == "on":
        def _socket_conn(url):
            try:
                getipport = urlparse(url)
                hostname = getipport.hostname
                port = getipport.port
                if port == None and r"https://" in url:
                    port = 443
                elif port == None and r"http://" in url:
                    port = 80
                else:
                    port = 80
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((hostname, port))
                sock.close()
                return "s"
            except socket.timeout:
                return "f"
            except ConnectionRefusedError:
                return "f"
            except:
                return "f"

        def _http_conn(url):
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
            # add by https://github.com/zhzyker/vulmap/issues/30 @zilong3033 fix url extract
            except requests.exceptions.InvalidURL:
                return "f"

        if _socket_conn(url) == "s":
            return "s"
        elif _http_conn(url) == "s":
            return "s"
        else:
            return "f"

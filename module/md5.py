#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import random
import string
import hashlib


def echo_md5():
    st = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    md = hashlib.md5("".join(st).encode('utf-8')).hexdigest()
    return str("echo " + md)


def random_md5():
    st = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    md = hashlib.md5("".join(st).encode('utf-8')).hexdigest()
    return str(md)

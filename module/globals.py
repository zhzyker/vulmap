#!/usr/bin/env python3
# -*- coding: utf-8 -*-

global _global_dict


def init():  # 初始化
    global _global_dict
    _global_dict = {}


def set_value(key, value):
    _global_dict[key] = value  # 定义一个全局变量


def get_value(key, def_value=None):
    try:
        return _global_dict[key]
    except KeyError:
        return def_value

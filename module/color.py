#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from thirdparty.colorama import init
from thirdparty.colorama import Fore, Back, Style, Cursor
init(autoreset=True)


class Colored:
    @staticmethod
    def magenta(s):
        return Style.BRIGHT+Fore.MAGENTA+s+Fore.RESET+Style.RESET_ALL
    @staticmethod
    def green(s):
        return Style.BRIGHT+Fore.GREEN+s+Fore.RESET+Style.RESET_ALL
    @staticmethod
    def white(s):
        return Fore.WHITE+s+Fore.RESET+Style.RESET_ALL
    @staticmethod
    def cyan(s):
        return Style.BRIGHT+Fore.CYAN+s+Fore.RESET+Style.RESET_ALL
    @staticmethod
    def cyan_fine(s):
        return Fore.CYAN+s+Fore.RESET+Style.RESET_ALL
    @staticmethod
    def yellow(s):
        return Style.BRIGHT+Fore.YELLOW+s+Fore.RESET+Style.RESET_ALL
    @staticmethod
    def red(s):
        return Style.BRIGHT+Fore.RED+s+Fore.RESET+Style.RESET_ALL
    @staticmethod
    def yel_info():
        return Style.BRIGHT+Fore.YELLOW+"[INFO]"+Fore.RESET+Style.RESET_ALL
    @staticmethod
    def red_warn():
        return Style.BRIGHT+Fore.RED+"[WARN]"+Fore.RESET+Style.RESET_ALL
    @staticmethod
    def rce():
        return "[rce]"
    @staticmethod
    def de_rce():
        return "[deserialization rce]"
    @staticmethod
    def upload():
        return "[upload]"
    @staticmethod
    def de_upload():
        return "[deserialization upload]"
    @staticmethod
    def de():
        return "[deserialization]"
    @staticmethod
    def contains():
        return "[file contains]"
    @staticmethod
    def xxe():
        return "[xxe]"
    @staticmethod
    def sql():
        return "[sql]"
    @staticmethod
    def ssrf():
        return "[ssrf]"


color = Colored()

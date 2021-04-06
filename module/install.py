#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import tarfile
import sysconfig
from module.time import now
from module.color import color
from module.banner import banner



def require():
    pwd_vulmap = os.path.split(os.path.realpath(sys.argv[0]))[0]
    def install_gevent():
        input_gevent = input(now.timed(de=0) + color.yel_info() + color.yellow(" Gevent dependency not found, install it now (y/n): "))
        if input_gevent == "y":
            try:
                pwd_packages = sysconfig.get_paths()["purelib"]
                os.chdir(pwd_vulmap)
                gevent_tar = "./thirdparty/gevent.tar.gz"
                t = tarfile.open(gevent_tar)
                t.extractall(path=pwd_packages)
                pwd_gevent = pwd_packages + "/gevent"
                os.chdir(pwd_gevent)
                try:
                    if os.system("python3 setup.py install >> /dev/null 2>&1") == 0:
                        print(now.timed(de=0) + color.yel_info() + color.yellow(" gevent install to: " + pwd_packages))
                        print(now.timed(de=0) + color.yel_info() + color.yellow(
                            " gevent dependency installation is complete"))
                    #print(now.timed(de=0) + color.red_warn() + color.yellow(
                    #    " Permission denied, need root permissions to install"))
                    #if os.system("sudo python3 setup.py install") == 0:
                    #    print(now.timed(de=0) + color.yel_info() + color.yellow(" Gevent install to: " + pwd_packages))
                    #    print(now.timed(de=0) + color.yel_info() + color.yellow(
                    #        " Gevent dependency installation is complete"))
                except:
                    print(now.timed(de=0) + color.red_warn() + color.yellow(
                        " gevent installation failed, please use \" pip3 install gevent\" to install"))
            except Exception as error:
                if r"Permission" in str(error):
                    print(now.timed(de=0) + color.red_warn() + color.yellow(
                        " Permission denied: Need root privileges or \"sudo xxxx\""))
                # print(now.timed(de=0) + color.red("[ERROR] " + error.__traceback__.tb_frame.f_globals['__file__']
                #                                  + " " + str(error.__traceback__.tb_lineno)))

    def install_crypto():
        input_crypto = input(now.timed(de=0) + color.yel_info() + color.yellow(" pycryptodome dependency not found, install it now (y/n): "))
        if input_crypto == "y":
            try:
                pwd_packages = sysconfig.get_paths()["purelib"]
                os.chdir(pwd_vulmap)
                pycryptodome_tar = "./thirdparty/pycryptodome.tar.gz"
                t = tarfile.open(pycryptodome_tar)
                t.extractall(path=pwd_packages)
                pwd_crypto = pwd_packages + "/pycryptodome"
                os.chdir(pwd_crypto)
                try:
                    if os.system("python3 setup.py install >> /dev/null 2>&1") == 0:
                        print(now.timed(de=0) + color.yel_info() + color.yellow(" pycryptodome install to: " + pwd_packages))
                        print(now.timed(de=0) + color.yel_info() + color.yellow(
                            " Crypto dependency installation is complete"))
                    #print(now.timed(de=0) + color.red_warn() + color.yellow(
                    #    " Permission denied, need root permissions to install"))
                    #if os.system("sudo python3 setup.py install") == 0:
                    #    print(now.timed(de=0) + color.yel_info() + color.yellow(" pycryptodome install to: " + pwd_packages))
                    #    print(now.timed(de=0) + color.yel_info() + color.yellow(
                    #        " pycryptodome dependency installation is complete"))
                except:
                    print(now.timed(de=0) + color.red_warn() + color.yellow(
                        " Crypto installation failed, please use \" pip3 install pycryptodome\" to install"))
            except Exception as error:
                if r"Permission" in str(error):
                    print(now.timed(de=0) + color.red_warn() + color.yellow(
                        " Permission denied: Need root privileges or \"sudo xxxx\""))

    require_list = []
    try:
        from gevent import monkey
        monkey.patch_all()
    except ImportError as e:
        print(now.timed(de=0) + color.red_warn() + color.yellow(" Not find \"gevent\", please use \" pip3 install -r requirements.txt\" to install"))
        exit(0)
        #if r"gevent" in str(e):
        #    require_list.append("gevent")
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
    except ImportError as e:
        print(now.timed(de=0) + color.red_warn() + color.yellow(" Not find \"pycryptodome\", please use \" pip3 install -r requirements.txt\" to install"))
        exit(0)
        #require_list.append("crypto")

    if r"gevent" in require_list and r"crypto" in require_list:
        print(banner())  # 显示随机banner
        install_gevent()
        install_crypto()
        exit(0)
    if r"gevent" in require_list:
        print(banner())  # 显示随机banner
        install_gevent()
        exit(0)
    if r"crypto" in require_list:
        print(banner())  # 显示随机banner
        install_crypto()
        exit(0)



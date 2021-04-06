#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import time
import json
import os.path
from module.time import now
from module.color import color
from module import globals
from urllib.parse import urlparse


def output(types, item):
    try:
        o_text = globals.get_value("O_TEXT")
        o_json = globals.get_value("O_JSON")
        if o_text and types == "text":
            output_text(o_text, item)
        elif o_json and types == "json":
            output_json(o_json, item)   
        else:
            pass
    except Exception as error:
        print(now.timed(de=0) + color.red("[ERROR] " + error.__traceback__.tb_frame.f_globals['__file__']
                                          + " " + str(error.__traceback__.tb_lineno)))


def output_text(filename, item):
    with open(filename, 'a') as output_file:
        output_file.write("%s\n" % item)


def output_json(filename, data):
    vul_data = data["vul_data"]
    raw_data = []
    try:
        if r">_<" in vul_data:
            vul_requ = vul_data
            vul_resp = vul_data
            vul_path = ""
        else:
            raw_data.append(vul_data)
            vul_requ = re.findall(r'([\s\S]*)\r\n> HTTP/', raw_data[0])[0]
            vul_requ = vul_requ.replace("< ", "")
            vul_resp = re.findall(r'\r\n> HTTP/([\s\S]*)', raw_data[0])[0]
            vul_resp = "HTTP/" + vul_resp.replace("> ", "")
            vul_path = re.findall(r' /(.*) HTTP', raw_data[0])[0]
    except Exception as error:
        print(now.timed(de=0) + color.red("[ERROR] " + error.__traceback__.tb_frame.f_globals['__file__']
                                          + " " + str(error.__traceback__.tb_lineno)))
        vul_path = ""
        vul_requ = ""
        vul_resp = ""

    try:
        vul_urls = data["vul_urls"]
        host_port = urlparse(vul_urls)
        vul_host = host_port.hostname
        vul_port = host_port.port
        # vul_u = vul_host + ":" + str(vul_port)
        if vul_port is None and r"https://" in vul_urls:
            vul_port = 443
        elif vul_port is None and r"http://" in vul_urls:
            vul_port = 80
        if r"https://" in vul_urls:
            if vul_port is not None:
                vul_u = "https://" + vul_host + ":" + str(vul_port) + "/" + vul_path
            else:
                vul_u = "https://" + vul_host + "/" + vul_path
        elif r"http://" in vul_urls:
            if vul_port is not None:
                vul_u = "http://" + vul_host + ":" + str(vul_port) + "/" + vul_path
            else:
                vul_u = "http://" + vul_host + "/" + vul_path
        else:
            vul_u = "http://" + vul_host + "/" + vul_path
        prt_name = data["prt_name"]
        vul_payd = data["vul_payd"]
        vul_type = data["vul_type"]
        vul_auth = data["cre_auth"]
        vul_desc = data["vul_name"]
        vul_date = int(round(time.time() * 1000))
        json_result = []
        json_data = {
            "create_time": vul_date,
            "detail": {
                "author": vul_auth,
                "description": vul_desc,
                "host": vul_host,
                "param": {},
                "payload": vul_payd,
                "port": vul_port,
                "request": vul_requ,
                "response": vul_resp,
                "url": vul_u
            },
            "plugin": prt_name,
            "target": {
                "url": vul_urls
            },
            "vuln_class": vul_type
        }
        json_result.append(json_data)

        def write_json(obj):
            item_list = []
            if os.path.isfile(filename):
                with open(filename, 'r') as f:
                    load_dict = json.load(f)
                    num_item = len(load_dict)
                    for i in range(num_item):
                        create_time = load_dict[i]['create_time']
                        author = load_dict[i]['detail']['author']
                        description = load_dict[i]['detail']['description']
                        host = load_dict[i]['detail']['host']
                        param = load_dict[i]['detail']['param']
                        payload = load_dict[i]['detail']['payload']
                        port = load_dict[i]['detail']['port']
                        request = load_dict[i]['detail']['request']
                        response = load_dict[i]['detail']['response']
                        url_1 = load_dict[i]['detail']['url']
                        plugin = load_dict[i]['plugin']
                        url_2 = load_dict[i]['target']['url']
                        vuln_class = load_dict[i]['vuln_class']
                        json_dict = {
                            "create_time": create_time,
                            "detail": {
                                "author": author,
                                "description": description,
                                "host": host,
                                "param": param,
                                "payload": payload,
                                "port": port,
                                "request": request,
                                "response": response,
                                "url": url_1
                            },
                            "plugin": plugin,
                            "target": {
                                "url": url_2
                            },
                            "vuln_class": vuln_class
                        }
                        item_list.append(json_dict)
            else:
                with open(filename, 'w', encoding='utf-8') as f2:
                    json.dump(json_result, f2, indent=4, ensure_ascii=False)
            item_list.append(obj)
            with open(filename, 'w', encoding='utf-8') as f2:
                json.dump(item_list, f2, indent=4, ensure_ascii=False)
        write_json(json_data)
    except Exception as error:
        print(now.timed(de=0) + color.red("[ERROR] " + error.__traceback__.tb_frame.f_globals['__file__']
                                          + " " + str(error.__traceback__.tb_lineno)))

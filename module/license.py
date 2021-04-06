#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import time
from module.allcheck import os_check
from module.output import output_text
from module.color import color
from module.time import now


def vulmap_license():
    pwd_vulmap = os.path.split(os.path.realpath(sys.argv[0]))[0]
    licenses = pwd_vulmap + "/module/licenses/licenses.txt"
    if os.path.isfile(licenses):
        pass
    else:
        print(color.white("Add the following " +
                          color.yellow("disclaimer") +
                          color.white(" to the original agreement (https://github.com/zhzyker/vulmap/blob/main/LICENSE). In case of conflict with the original agreement, the " +
                          color.yellow("disclaimer") +
                          color.white(" shall prevail.\n"))))

        print(color.white("Unauthorized commercial use of this tool is prohibited, and unauthorized commercial use after secondary development is prohibited\n\n"
                          "This tool is only for legally authorized corporate security construction activities. When using this tool for testing, you should ensure that the behavior complies with local laws and regulations and has obtained sufficient authorization.\n\n"
                          "If you have any illegal behavior in the process of using this tool, you need to bear the corresponding consequences yourself, and we will not bear any legal and joint liabilities.\n\n"
                          "Before using this tool, please read carefully and fully understand the content of each clause. Restrictions, exemptions, or other clauses involving your major rights and interests may be bolded, underlined, etc. to remind you to pay attention. Unless you have fully read, fully understood and accepted all the terms of this agreement, please do not use this tool. Your use behavior or your acceptance of this agreement in any other express or implied manner shall be deemed to have been read and agreed to be bound by this agreement.\n"
                          ))
        print(color.white("------------------------------------------------------------------\n"))
        print(color.white("在原有协议(https://github.com/zhzyker/vulmap/blob/main/LICENSE)中追加以下" +
                          color.yellow("免责声明。") +
                          color.white("若与原有协议冲突均以") +
                          color.yellow("免责声明") + color.white("为准。\n")))
        print(color.white("本工具禁止进行未授权商业用途，禁止二次开发后进行未授权商业用途\n\n"
                          "本工具仅面向合法授权的企业安全建设行为，在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。\n\n"
                          "如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。\n\n"
                          "在使用本工具前，请您务必审慎阅读、充分理解各条款内容，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。 除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。\n"
                          ))
        if os_check() == "linux" or os_check() == "other":
            lic = input(now.timed(de=0) + color.yellow("[*] I accept the disclaimer (yes/no): "))
            if lic == "yes" or lic == "y":
                create_date = int(round(time.time() * 1000))
                output_text(licenses, create_date)
            else:
                print(now.timed(de=0) + color.red_warn() + color.red(" Good Lucking"))
                exit(0)
        elif os_check() == "windows":
            lic = input(now.no_color_timed(de=0) + "[*] I accept the disclaimer (yes/no): ")
            if lic == "yes" or lic == "y":
                create_date = int(round(time.time() * 1000))
                output_text(licenses, create_date)
            else:
                print(now.timed(de=0) + color.red_warn() + color.red(" Good Lucking"))
                exit(0)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from gevent import spawn
from payload.ApacheAcitveMQ import ApacheActiveMQ
from payload.ApacheFlink import ApacheFlink
from payload.ApacheShiro import ApacheShiro
from payload.ApacheSolr import ApacheSolr
from payload.ApacheTomcat import ApacheTomcat
from payload.Fastjson import Fastjson
from payload.Elasticsearch import Elasticsearch
from payload.Jenkins import Jenkins
from payload.OracleWeblogic import OracleWeblogic
from payload.Spring import Spring
from payload.Nexus import Nexus
from payload.RadHatJBoss import RedHatJBoss
from payload.ApacheUnomi import ApacheUnomi
from payload.ThinkPHP import ThinkPHP
from payload.Drupal import Drupal
from payload.ApacheStruts2 import ApacheStruts2
from payload.ApacheDruid import ApacheDruid
from payload.Laravel import Laravel
from payload.Vmware import Vmware
from payload.SaltStack import SaltStack
from payload.NodeJs import NodeJs
from payload.Exchange import Exchange
from payload.F5_BIG_IP import BIG_IP
from payload.ApacheOFBiz import ApacheOFBiz
from payload.QiAnXin import QiAnXin
from payload.RuiJie import RuiJie
from payload.Eyou import Eyou
from payload.CoreMail import CoreMail
from payload.Ecology import Ecology


class Scan():

    def apache_activemq(self, target, gevent_pool):
        poc_apache_activemq = ApacheActiveMQ(target)
        gevent_pool.append(spawn(poc_apache_activemq.cve_2015_5254_poc))
        gevent_pool.append(spawn(poc_apache_activemq.cve_2016_3088_poc))

    def apache_flink(self, target, gevent_pool):
        poc_apache_flink = ApacheFlink(target)
        gevent_pool.append(spawn(poc_apache_flink.cve_2020_17518_poc))
        gevent_pool.append(spawn(poc_apache_flink.cve_2020_17519_poc))

    def apache_shiro(self, target, gevent_pool):
        poc_apache_shiro = ApacheShiro(target)
        gevent_pool.append(spawn(poc_apache_shiro.cve_2016_4437_poc))

    def apache_solr(self, target, gevent_pool):
        poc_apache_solr = ApacheSolr(target)
        gevent_pool.append(spawn(poc_apache_solr.cve_2017_12629_poc))
        gevent_pool.append(spawn(poc_apache_solr.cve_2019_0193_poc))
        gevent_pool.append(spawn(poc_apache_solr.cve_2019_17558_poc))
        gevent_pool.append(spawn(poc_apache_solr.time_2021_0318_poc))
        gevent_pool.append(spawn(poc_apache_solr.cve_2021_27905_poc))


    def apache_tomcat(self, target, gevent_pool):
        poc_apache_tomcat = ApacheTomcat(target)
        gevent_pool.append(spawn(poc_apache_tomcat.tomcat_examples_poc))
        gevent_pool.append(spawn(poc_apache_tomcat.cve_2017_12615_poc))
        gevent_pool.append(spawn(poc_apache_tomcat.cve_2020_1938_poc))

    def fastjson(self, target, gevent_pool):
        poc_apache_solr = Fastjson(target)
        gevent_pool.append(spawn(poc_apache_solr.fastjson_1224_1_poc))
        gevent_pool.append(spawn(poc_apache_solr.fastjson_1224_2_poc))
        gevent_pool.append(spawn(poc_apache_solr.fastjson_1224_3_poc))
        gevent_pool.append(spawn(poc_apache_solr.fastjson_1247_poc))
        gevent_pool.append(spawn(poc_apache_solr.fastjson_1262_poc))

    def spring(self, target, gevent_pool):
        poc_spring = Spring(target)
        gevent_pool.append(spawn(poc_spring.cve_2020_5410_poc))
        gevent_pool.append(spawn(poc_spring.cve_2019_3799_poc))
        gevent_pool.append(spawn(poc_spring.cve_2018_1273_poc))

    def elasticsearch(self, target, gevent_pool):
        poc_elasticsearch = Elasticsearch(target)
        gevent_pool.append(spawn(poc_elasticsearch.cve_2015_1427_poc))
        gevent_pool.append(spawn(poc_elasticsearch.cve_2014_3120_poc))

    def jenkins(self, target, gevent_pool):
        poc_jenkins = Jenkins(target)
        gevent_pool.append(spawn(poc_jenkins.cve_2017_1000353_poc))
        gevent_pool.append(spawn(poc_jenkins.cve_2018_1000861_poc))

    def oracle_weblogic(self, target, gevent_pool):
        poc_oracle_weblogic = OracleWeblogic(target)
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2014_4210_poc))
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2020_14882_poc))
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2016_0638_poc))
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2017_3506_poc))
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2017_10271_poc))
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2018_2894_poc))
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2018_3191_poc))
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2019_2725_poc))
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2019_2890_poc))
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2020_2555_poc))
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2019_2729_poc))
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2020_2883_poc))
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2020_2551_poc))
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2021_2109_poc))

    def nexus(self, target, gevent_pool):
        poc_nexus = Nexus(target)
        gevent_pool.append(spawn(poc_nexus.cve_2019_7238_poc))
        gevent_pool.append(spawn(poc_nexus.cve_2020_10199_poc))

    def redhat_jboss(self, target, gevent_pool):
        poc_redhat_jboss = RedHatJBoss(target)
        gevent_pool.append(spawn(poc_redhat_jboss.cve_2010_0738_poc))
        gevent_pool.append(spawn(poc_redhat_jboss.cve_2010_1428_poc))
        gevent_pool.append(spawn(poc_redhat_jboss.cve_2015_7501_poc))
        gevent_pool.append(spawn(poc_redhat_jboss.cve_2017_12149_poc))

    def apache_unomi(self, target, gevent_pool):
        poc_apache_unomi = ApacheUnomi(target)
        gevent_pool.append(spawn(poc_apache_unomi.cve_2020_13942_poc))

    def thinkphp(self, target, gevent_pool):
        poc_thinkphp = ThinkPHP(target)
        gevent_pool.append(spawn(poc_thinkphp.cve_2019_9082_poc))
        gevent_pool.append(spawn(poc_thinkphp.cve_2018_20062_poc))

    def drupal(self, target, gevent_pool):
        poc_drupal = Drupal(target)
        gevent_pool.append(spawn(poc_drupal.cve_2018_7600_poc))
        gevent_pool.append(spawn(poc_drupal.cve_2018_7602_poc))
        gevent_pool.append(spawn(poc_drupal.cve_2019_6340_poc))

    def apache_strtus2(self, target, gevent_pool):
        poc_apache_struts2 = ApacheStruts2(target)
        gevent_pool.append(spawn(poc_apache_struts2.s2_005_poc))
        gevent_pool.append(spawn(poc_apache_struts2.s2_008_poc))
        gevent_pool.append(spawn(poc_apache_struts2.s2_009_poc))
        gevent_pool.append(spawn(poc_apache_struts2.s2_013_poc))
        gevent_pool.append(spawn(poc_apache_struts2.s2_015_poc))
        gevent_pool.append(spawn(poc_apache_struts2.s2_016_poc))
        gevent_pool.append(spawn(poc_apache_struts2.s2_029_poc))
        gevent_pool.append(spawn(poc_apache_struts2.s2_032_poc))
        gevent_pool.append(spawn(poc_apache_struts2.s2_045_poc))
        gevent_pool.append(spawn(poc_apache_struts2.s2_046_poc))
        gevent_pool.append(spawn(poc_apache_struts2.s2_048_poc))
        gevent_pool.append(spawn(poc_apache_struts2.s2_052_poc))
        gevent_pool.append(spawn(poc_apache_struts2.s2_057_poc))
        gevent_pool.append(spawn(poc_apache_struts2.s2_059_poc))
        gevent_pool.append(spawn(poc_apache_struts2.s2_061_poc))
        gevent_pool.append(spawn(poc_apache_struts2.s2_devMode_poc))

    def apache_druid(self, target, gevent_pool):
        poc_apache_druid = ApacheDruid(target)
        gevent_pool.append(spawn(poc_apache_druid.cve_2021_25646_poc))

    def laravel(self, target, gevent_pool):
        poc_laravel = Laravel(target)
        gevent_pool.append(spawn(poc_laravel.cve_2021_3129_poc))

    def vmware(self, target, gevent_pool):
        poc_vmware = Vmware(target)
        gevent_pool.append(spawn(poc_vmware.time_2020_1013_poc))
        gevent_pool.append(spawn(poc_vmware.cve_2021_21972_poc))
        gevent_pool.append(spawn(poc_vmware.cve_2021_21975_poc))

    def saltstack(self, target, gevent_pool):
        poc_saltstack = SaltStack(target)
        gevent_pool.append(spawn(poc_saltstack.cve_2021_25282_poc))

    def nodejs(self, target, gevent_pool):
        poc_nodejs = NodeJs(target)
        gevent_pool.append(spawn(poc_nodejs.cve_2021_21315_poc))

    def exchange(self, target, gevent_pool):
        poc_exchange = Exchange(target)
        gevent_pool.append(spawn(poc_exchange.cve_2021_26855_poc))
        gevent_pool.append(spawn(poc_exchange.cve_2021_27065_poc))

    def big_ip(self, target, gevent_pool):
        poc_big_ip = BIG_IP(target)
        gevent_pool.append(spawn(poc_big_ip.cve_2021_22986_poc))
        gevent_pool.append(spawn(poc_big_ip.cve_2020_5902_poc))

    def apache_ofbiz(self, target, gevent_pool):
        apache_ofbiz = ApacheOFBiz(target)
        gevent_pool.append(spawn(apache_ofbiz.cve_2021_26295_poc))
        gevent_pool.append(spawn(apache_ofbiz.cve_2021_30128_poc))
        gevent_pool.append(spawn(apache_ofbiz.cve_2021_29200_poc))

    def qiaixin(self, target, gevent_pool):
        qianxin = QiAnXin(target)
        gevent_pool.append(spawn(qianxin.time_2021_0410_poc))

    def ruijie(self, target, gevent_pool):
        ruijie = RuiJie(target)
        gevent_pool.append(spawn(ruijie.time_2021_0424_poc))

    def eyou(self, target, gevent_pool):
        eyou = Eyou(target)
        gevent_pool.append(spawn(eyou.cnvd_2021_26422_poc))

    def coremail(self, target, gevent_pool):
        coremail = CoreMail(target)
        gevent_pool.append(spawn(coremail.time_2021_0414_poc))

    def ecology(self, target, gevent_pool):
        ecology = Ecology(target)
        gevent_pool.append(spawn(ecology.time_2021_0515_poc))


scan = Scan()

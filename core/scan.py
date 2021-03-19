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

    def apache_tomcat(self, target, gevent_pool):
        poc_apache_tomcat = ApacheTomcat(target)
        gevent_pool.append(spawn(poc_apache_tomcat.tomcat_examples_poc))
        gevent_pool.append(spawn(poc_apache_tomcat.cve_2017_12615_poc))
        gevent_pool.append(spawn(poc_apache_tomcat.cve_2020_1938_poc))

    def fastjson(self, target, gevent_pool):
        poc_apache_solr = Fastjson(target)
        gevent_pool.append(spawn(poc_apache_solr.fastjson_1224_poc))
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
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2017_3506_poc))
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2017_10271_poc))
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2018_2894_poc))
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2019_2725_poc))
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2019_2729_poc))
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2020_2555_poc))
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2020_2551_poc))
        gevent_pool.append(spawn(poc_oracle_weblogic.cve_2020_2883_poc))

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

scan = Scan()

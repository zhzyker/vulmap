
## Vulmap 
Vulmap - это инструмент сканирования уязвимостей, который может сканировать на наличие уязвимостей в веб-контейнерах, веб-серверах, промежуточном веб-программном обеспечении, а также в CMS и других веб-программах, а также имеет функции эксплуатации уязвимостей.
Соответствующие тестировщики могут использовать vulmap, чтобы определить, есть ли у цели конкретная уязвимость, и могут использовать функцию эксплуатации уязвимости, чтобы проверить, существует ли уязвимость на самом деле.

В настоящее время Vulmap имеет режимы сканирования уязвимостей (poc) и эксплуатации (exp). Используйте "-m", чтобы выбрать, какой режим использовать, и режим poc по умолчанию является режимом по умолчанию. В режиме poc он также поддерживает "-f" сканирование целей в пакетном режиме, "-o" результаты вывода файла и другие основные функции; дополнительные функции см. в разделе Параметры или python3 vulmap.py -h, в режиме эксплойта эксплойта функция poc больше не будет предоставляться, но эксплойт будет выполняться напрямую, а результат эксплойта будет отправлен обратно. Далее проверьте, существует ли уязвимость и можно ли ее использовать.

Программа полностью написана на python3, если у вас есть среда python3 в операционной системе, она может работать в Linux, MacOS и Windows. Рекомендуется использовать python3.7 или выше. Vulmap в настоящее время имеет только интерфейс командной строки (CLI), поэтому вам необходимо Запуск в командной строке, подробные инструкции см. В разделе Параметры.

## Installation
* монтажная зависимость
```
pip3 install -r requirements.txt
```
* Linux & MacOS & Windows
```
python3 vulmap.py -u http://example.com
```

## Options
``` 
  -h, --help            Показать это справочное сообщение и выйти
  -u URL, --url URL     Целевой URL (пример: -u "http://example.com")
  -f FILE, --file FILE  Выберите файл целевого списка, каждый URL-адрес должен выделяться строкой (пример: -f "/home/user/list.txt")
  -m MODE, --mode MODE  Режим поддерживает "poc" и "exp", вы можете опустить этот параметр и по умолчанию перейти в режим "poc".
  -a APP, --app APP     Укажите веб-контейнер, веб-сервер, промежуточное программное обеспечение или CMD (например: "weblogic"), если не указано, сканировать все по умолчанию.
  -c CMD, --cmd CMD     Настройте команду, выполняемую удаленной командой. Если это не "netstat -an" и "id", это может повлиять на оценку программы. По умолчанию используется "netstat -an"
  -v VULN, --vuln VULN  Чтобы использовать уязвимость, необходимо указать номер уязвимости (пример: -v "CVE-2020-2729").
  --list                Показать список поддерживаемых уязвимостей
  --debug               Режим отладки, будет отображать запрос и ответы
  --delay DELAY         Время задержки, как часто отправляется, по умолчанию 0 с.
  --timeout TIMEOUT     Время ожидания, по умолчанию 10 с
  --output FILE         Вывод результата в текстовом режиме (Пример: -o "result.txt")
```
## Examples
Проверить все уязвимости poc
```
python3 vulmap.py -u http://example.com
```
Для уязвимостей RCE используйте команду id, чтобы определить, есть ли уязвимости, потому что в отдельных системах Linux нет команды "netstat -an".
```
python3 vulmap.py -u http://example.com -c "id"
```

Проверьте http://example.com на наличие уязвимости struts2
```
python3 vulmap.py -u http://example.com -a struts2
```
```
python3 vulmap.py -u http://example.com -m poc -a struts2
```
Воспользуйтесь уязвимостью CVE-2019-2729 в WebLogic на http://example.com:7001
```
python3 vulmap.py -u http://example.com:7001 -v CVE-2019-2729
```
```
python3 vulmap.py -u http://example.com:7001 -m exp -v CVE-2019-2729
```
URL-адреса пакетного сканирования в list.txt
```
python3 vulmap.py -f list.txt
```
Экспорт результатов сканирования в result.txt
```
python3 vulmap.py -u http://example.com:7001 -o result.txt
```

## Vulnerabilitys List
Уязвимости, поддерживаемые vulmap, следующие:
```
 +-------------------+------------------+-----+-----+-------------------------------------------------------------+
 | Target type       | Vuln Name        | Poc | Exp | Impact Version && Vulnerability description                 |
 +-------------------+------------------+-----+-----+-------------------------------------------------------------+
 | Apache Solr       | CVE-2017-12629   |  Y  |  Y  | < 7.1.0, runexecutablelistener rce & xxe, only rce is here  |
 | Apache Solr       | CVE-2019-0193    |  Y  |  Y  | < 8.2.0, dataimporthandler module remote code execution     |
 | Apache Solr       | CVE-2019-17558   |  Y  |  Y  | 5.0.0 - 8.3.1, velocity response writer rce                 |
 | Apache Struts2    | S2-005           |  Y  |  Y  | 2.0.0 - 2.1.8.1, cve-2010-1870 parameters interceptor rce   |
 | Apache Struts2    | S2-008           |  Y  |  Y  | 2.0.0 - 2.3.17, debugging interceptor rce                   |
 | Apache Struts2    | S2-009           |  Y  |  Y  | 2.1.0 - 2.3.1.1, cve-2011-3923 ognl interpreter rce         |
 | Apache Struts2    | S2-013           |  Y  |  Y  | 2.0.0 - 2.3.14.1, cve-2013-1966 ognl interpreter rce        |
 | Apache Struts2    | S2-015           |  Y  |  Y  | 2.0.0 - 2.3.14.2, cve-2013-2134 ognl interpreter rce        |
 | Apache Struts2    | S2-016           |  Y  |  Y  | 2.0.0 - 2.3.15, cve-2013-2251 ognl interpreter rce          |
 | Apache Struts2    | S2-029           |  Y  |  Y  | 2.0.0 - 2.3.24.1, ognl interpreter rce                      |
 | Apache Struts2    | S2-032           |  Y  |  Y  | 2.3.20-28, cve-2016-3081 rce can be performed via method    |
 | Apache Struts2    | S2-045           |  Y  |  Y  | 2.3.5-31, 2.5.0-10, cve-2017-5638 jakarta multipart rce     |
 | Apache Struts2    | S2-046           |  Y  |  Y  | 2.3.5-31, 2.5.0-10, cve-2017-5638 jakarta multipart rce     |
 | Apache Struts2    | S2-048           |  Y  |  Y  | 2.3.x, cve-2017-9791 struts2-struts1-plugin rce             |
 | Apache Struts2    | S2-052           |  Y  |  Y  | 2.1.2 - 2.3.33, 2.5 - 2.5.12 cve-2017-9805 rest plugin rce  |
 | Apache Struts2    | S2-057           |  Y  |  Y  | 2.0.4 - 2.3.34, 2.5.0-2.5.16, cve-2018-11776 namespace rce  |
 | Apache Struts2    | S2-059           |  Y  |  Y  | 2.0.0 - 2.5.20 cve-2019-0230 ognl interpreter rce           |
 | Apache Struts2    | S2-devMode       |  Y  |  Y  | 2.1.0 - 2.5.1, devmode remote code execution                |
 | Apache Tomcat     | Examples File    |  Y  |  N  | all version, /examples/servlets/servlet/SessionExample      |
 | Apache Tomcat     | CVE-2017-12615   |  Y  |  Y  | 7.0.0 - 7.0.81, put method any files upload                 |
 | Apache Tomcat     | CVE-2020-1938    |  Y  |  Y  | 6, 7 < 7.0.100, 8 < 8.5.51, 9 < 9.0.31 arbitrary file read  |
 | Drupal            | CVE-2018-7600    |  Y  |  Y  | 6.x, 7.x, 8.x, drupalgeddon2 remote code execution          |
 | Drupal            | CVE-2018-7602    |  Y  |  Y  | < 7.59, < 8.5.3 (except 8.4.8) drupalgeddon2 rce            |
 | Jenkins           | CVE-2017-1000353 |  Y  |  N  | <= 2.56, LTS <= 2.46.1, jenkins-ci remote code execution    |
 | Jenkins           | CVE-2018-1000861 |  Y  |  Y  | <= 2.153, LTS <= 2.138.3, remote code execution             |
 | Nexus OSS/Pro     | CVE-2019-7238    |  Y  |  Y  | 3.6.2 - 3.14.0, remote code execution vulnerability         |
 | Nexus OSS/Pro     | CVE-2020-10199   |  N  |  Y  | 3.x  <= 3.21.1, remote code execution vulnerability         |
 | Oracle Weblogic   | CVE-2014-4210    |  Y  |  N  | 10.0.2 - 10.3.6, weblogic ssrf vulnerability                |
 | Oracle Weblogic   | CVE-2017-3506    |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.0-2, weblogic wls-wsat rce       |
 | Oracle Weblogic   | CVE-2017-10271   |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.1-2, weblogic wls-wsat rce       |
 | Oracle Weblogic   | CVE-2018-2894    |  Y  |  Y  | 12.1.3.0, 12.2.1.2-3, deserialization any file upload       |
 | Oracle Weblogic   | CVE-2019-2725    |  Y  |  Y  | 10.3.6.0, 12.1.3.0, weblogic wls9-async deserialization rce |
 | Oracle Weblogic   | CVE-2019-2729    |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.3 wls9-async deserialization rce |
 | Oracle Weblogic   | CVE-2020-2551    |  Y  |  N  | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, wlscore deserialization rce |
 | RedHat JBoss      | CVE-2010-0738    |  Y  |  Y  | 4.2.0 - 4.3.0, jmx-console deserialization any files upload |
 | RedHat JBoss      | CVE-2010-1428    |  Y  |  Y  | 4.2.0 - 4.3.0, web-console deserialization any files upload |
 | RedHat JBoss      | CVE-2015-7501    |  Y  |  Y  | 5.x, 6.x, jmxinvokerservlet deserialization any file upload |
 +-------------------+------------------+-----+-----+-------------------------------------------------------------+
```

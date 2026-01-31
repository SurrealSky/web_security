信息搜集
========================================

确定目标
----------------------------------------
+ 专属SRC
    - 要选容易优质的SRC
+ 明确测试范围
    - 通过SRC活动页面，查看测试目标域名范围
+ 优先级
    - APP>小程序>web网站>其他

顶级域名收集
----------------------------------------
+ ICP备案查询
    + 通过ICP备案号查询注册的域名，比如百度的备案号是 ``京ICP证030173号``
    + 工信部ICP/IP地址/域名信息备案管理系统: ``https://beian.miit.gov.cn``
    + 爱站网: ``https://icp.aizhan.com/``
    + 工具：``https://github.com/HG-ha/ICP_Query``
+ 爱企查获取公司所属域名
    搜索想要测试等SRC所属公司名称，在知识产权->网站备案中可以获取测试范围。
+ firefly: ``https://firefly-src.geekyoung.com``
+ 零零信安暴露面检测：``https://0.zone/exposure``

子域名收集
----------------------------------------
+ 使用oneforall扫描获取子域名
+ 使用fofa搜索子域名
+ 使用Layer挖掘机进行
+ 使用arl灯塔
+ 命令行工具
    - crtsh: ``curl -s https://crt.sh\?q\=\example.com\&output\=json | jq -r '.[].name_value' | grep -Po '(\w+\.\w+\.\w+)$' >crtsh.txt``
    - virustotal: ``curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=example.com&apikey=[api-key]" | jq -r '.subdomains[]' > vt.txt``
    - waybackurls: ``curl -s "http://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=text&fl=original&collapse=urlkey" |sort| sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | sort -u > wayback.txt``
    - alienvault OTX: ``curl -s "https://otx.alienvault.com/api/v1/indicators/domain/example.com/url_list?limit=500&page=1" | jq -r '.subdomains[]' | sed 's/\.example\.com$//g' > otx.txt``
    - sublist3r: ``sublist3r -d example.com -e baidu,yahoo,google,bing,ask,netcraft,virustotal,threatcrowd,crtsh,passivedns -v -o sublist3r.txt``
    - subfinder: ``subfinder -d yuanqisousou.com -o subdomains.txt``
    - urlscan: ``curl -s "https://urlscan.io/api/v1/search/?q=domain:example.com&size=10000" | jq -r '.results[]?.page?.domain' | sort -u > urlscan.txt``
+ 联动命令
    ::

        subfinder -d example.com -all -recursive | alterx | dnsx -silent | tee -a subdomains.txt
        chaos -d example.com | dnsx | httpx | nuclei

        httpx -silent -status-code -title -tech-detect -follow-redirects -ports 80,8080,443,8000 -mc 200,302,403,401,500
+ 合并去重 ： ``cat *.txt | sort -u > all_subdomains.txt``

ip收集
---------------------------------------
+ httpx: ``httpx -l subdomains.txt -ip | sed -nE 's/.*\[([0-9.]+)\].*/\1/p'|sort -u > ip.txt``

批量端口扫描
----------------------------------------
+ naabu
    - ``cat all_subdomains.txt | naabu -top-ports 100 | tee -a ports.txt``
    - ``naabu -l ip.txt -top-ports 100 -rate 1500 -verify -silent -o naabu.txt``

端口服务探测
----------------------------------------
+ naabutonmap.py
    - 地址： ``https://github.com/coffinxp/scripts/blob/main/naabutonmap.py``
    - 原理： 调用nmap进行
    - 命令： ``python3 naabutonmap.py -i naabu.txt``
    - 结果解析
        ::

            https://github.com/ernw/nmap-parse-output
            ./nmap-parse-output nmap-out.xml html > scan_out.html
            浏览器打开scan_out.html

web指纹识别
----------------------------------------
+ whatweb
    - 项目地址： ``https://github.com/urbanadventurer/WhatWeb/wiki/Installation``
    - 安装： ``sudo yum install whatweb``
    - 使用： ``whatweb -t 50 -i ports.txt --log-brief=whatweb.txt``
    - 详细用法： ``whatweb -t 50 -i ports.txt --log-brief=whatweb.txt --aggressive``

URL爬取
----------------------------------------
+ 主动爬取
    ::

        katana -u ports.txt -d 2 -o url1.txt

        执行hakrawler，需要在url前加上http://
        sed 's/^/http:\/\//' ports.txt > ports_http.txt
        cat ports.txt | hakrawler -u > url2.txt

        模糊测试：
        ffuf -w ip.txt:SUB -w /home/coffinxp/payloads/back_files_only.txt:FILE -u https://SUB/FILE -mc 200 -rate 50 -fs 0 -c -fw 3,117

+ 被动爬取
    ::

        echo example.com | gau --mc 200 | urldedupe > url3.txt
        urlfinder -u example.com | sort -u > url4.txt

        curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=example.com&apikey=[api-key]" > vt_all.txt
        curl -s "https://otx.alienvault.com/api/v1/indicators/domain/example.com/url_list?limit=500&page=1" | jq -r '.url_list[].url' > otx_urls.txt
        curl -s "http://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=text&fl=original&collapse=urlkey" | sort > wayback_all.txt

+ URL清洗
    - ``cat *.txt | uro | sort -u >uro.txt``

web资产
----------------------------------------

URL敏感信息提取
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ gf
    ::
        
        debug_logic,idor,img-traversal,interestingEXT,interestingparams,interestingsubs
        jsvar,lfi,rce,redirect,sqli,ssrf,ssti,xss
        cat url*.txt | gf xss | sort -u > xss.txt
+ ``cat *.txt | grep -E "\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5"``
+ ``cat *.txt | grep -E "\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|tar|xz|7zip|p12|pem|key|crt|csr|sh|pl|py|java|class|jar|war|ear|sqlitedb|sqlite3|dbf|db3|accdb|mdb|sqlcipher|gitignore|env|ini|conf|properties|plist|cfg)$"``
+ google hacker: ``site:*.example.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)``

js敏感信息收集
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ ``python js_info_finder.py -u http://example.com``

帮助手册/演示视频
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 泄露用户名/密码
+ 泄露API

PC资产
----------------------------------------

APP资产
----------------------------------------

小程序公众号资产
----------------------------------------
+ 小程序抓包、APP抓包参考链接：
    ::
    
        https://mp.weixin.qq.com/s/xuoVxBsN-t5KcwuyGpR56g
        https://mp.weixin.qq.com/s/45YF4tBaR-TUsHyF5RvEsw
        https://mp.weixin.qq.com/s/M5xu_-_6fgp8q0KjpzvjLg
        https://mp.weixin.qq.com/s/Mfkbxtrxv5AvY-n_bMU7ig

推荐网站
----------------------------------------
+ 包含SRC通道和在线工具：https://index.tesla-space.com/
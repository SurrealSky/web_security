SRC漏洞挖掘思路
========================================

确定目标
----------------------------------------
+ 专属SRC

测试范围
----------------------------------------
+ 通过SRC活动页面，查看测试目标域名范围
+ 爱企查获取公司所属域名
    搜索想要测试等SRC所属公司名称，在知识产权->网站备案中可以获取测试范围。

子域名
----------------------------------------
+ 使用oneforall扫描获取子域名

系统指纹探测
----------------------------------------
+ 使用Ehole
+ 使用Glass

框架站点漏洞测试
----------------------------------------
+ Nday漏洞

非框架型站点漏洞测试
----------------------------------------
+ 登录框
    - 用户名枚举
    - 验证码绕过/置空
    - 暴力破解
    - 自行注册

端口扫描
----------------------------------------
+ ``sudo nmap -sS -Pn -n --open --min-hostgroup 4 --min-parallelism 1024 --host-timeout 30 -T4 -v  examples.comsudo nmap -sS -Pn -n --open --min-hostgroup 4 --min-parallelism 1024 --host-timeout 30 -T4 -v -p 1-65535 examples.com``

目录扫描
----------------------------------------
+ ``python3 dirsearch.py -u www.xxx.com -e * -t 2``

JS信息搜集
----------------------------------------
+ JSFinder

小程序/公众号
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
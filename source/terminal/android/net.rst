抓包思路
========================================

直接抓包
----------------------------------------
+ ecapture
	- 项目地址：https://github.com/gojue/ecapture
	- 支持：Linux/Android kernel versions x86_64 4.18 and above, aarch64 5.5 and above
	- 指令： ``./ecapture tls -m pcap -i wlan0 --pcapfile=ups.pcapng``

不走代理
----------------------------------------
+ 现象
	- 配置完全ok
	- burp中没有任何数据包
	- APP使用正常，网络正常
+ 可能原因：APP使用的网络库设置了不走任何代理
+ 解决方案
	- iptables流量转发
		+ burp设置 **支持隐形代理**
		+ 获取目标应用UID： ``ps -A | grep <包名>`` ，第一列就是UID
		+ 转发流量： ``iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner <UID> -j DNAT --to-destination <burp-ip>:<burp-port>``
		+ 清除规则： ``iptables -t nat -F``
		+ 查看规则： ``iptables -t nat -L OUTPUT -v -n``
	- postern、Super Proxy等VPN工具
		+ 是一个VPN
		+ VPN里面可以设置代理（HTTP）为burp。
	- httpcanary
		+ 手机上的一个抓包工具。
	- http analyzer
		+ 结合模拟器，抓取模拟器进程的数据包。
	- hook方式绕过
		+ 原理：根据APP使用的不同的网络框架进行hook。
		+ 如HttpURLConnection、OkHttp、Volley等，hook相关的函数，绕过代理检测。

代理/VPN检测
----------------------------------------
+ 现象
	- 应用弹框提示："检测到VPN/网络代理，无法使用"
	- 闪退
+ 通杀方法
	- 原理：电脑开启wifi热点（wifi共享大师），使用Proxifier设置代理，将流量转发到burp，这样手机端不用设置任何代理。
	- burp设置代理
	- 电脑开启wifi热点，手机连接热点
	- 全局代理：Proxifier设置代理服务器端口为burp监听的地址和端口,规则里面选择wifi共享大师进程。

HTTPS单向证书校验
----------------------------------------
+ 现象：APP使用中网络请求失败，网络错误等。
+ 原理：校验了服务器证书，这样的话，burp代理的证书就会被APP拒绝，无法抓包。
+ 解决方案：

HTTPS双向证书校验
----------------------------------------
+ 现象：BURP可以抓到客户端发出的请求，但服务器没有响应，或者响应错误。
+ 原理：除了客户端会校验服务器证书外，服务器端会校验客户端的请求证书，burp的证书会被服务器检测出来。

非常规HTTPS
----------------------------------------
+ 原理：SSL的lib库是自己改过的，证券类的应用比较多。
网络抓包
========================================

本机直接抓包
----------------------------------------
+ ecapture 
	- 项目地址：https://github.com/gojue/ecapture
	- 支持：基于手机ebpf支持L，inux/Android kernel versions  **x86_64 4.18 and above** , **aarch64 5.5 and above**
	- 指令： ``./ecapture tls -m pcap -i wlan0 --pcapfile=ups.pcapng``
+ httpcanary
	- 项目地址：网盘下载
	- 支持：Android 5.0及以上
	- 原理：基于Android的 **VPNService** 创建本地虚拟专用网络，HTTP Canary通过这个VPN，充当 **代理** 与真实服务器通信（所以同样需要安装证书），从而捕获手机上的网络流量。

传统代理
----------------------------------------
+ 手机安装证书（如burp/fiddler）
+ 网络连接-高级-设置代理-手动-输入代理服务器地址和端口
+ 电脑端burp/fiddler开启代理工具，监听对应的端口，开始抓包

透明代理
----------------------------------------
+ vpn类
	- postern、Super Proxy等VPN工具将流量封装为标准的代理协议，转发给代理服务器。
+ 内核转发类
	- iptables:仅负责流量转发，不负责协议转换。
	- readsocks：协议翻译器，负责将接受的流量转换成SOCKS或HTTPS代理协议。
	- 两者需要配合使用，才能将流量转发给代理服务器。
	- 实现方法
		+ burp设置 **支持隐形代理** ,可以接受直接转发的流量，而不需要协议转发器。
		+ 获取目标应用UID： ``ps -A | grep <包名>`` ，第一列就是UID
		+ 转发流量： ``iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner <UID> -j DNAT --to-destination <burp-ip>:<burp-port>``
		+ 清除规则： ``iptables -t nat -F``
		+ 查看规则： ``iptables -t nat -L OUTPUT -v -n``
		+ 协议转换：使用readsocks将流量转换成SOCKS或HTTPS代理协议，转发给burp。
			::

				readsocks配置文件示例：
				[general]
				log_level = "info"
				log_file = "readsocks.log"

				[socks5]
				type = "socks5"
				server = "<burp-ip>:<burp-port>"
				timeout = 300

+ 模拟器
	- 使用模拟器，将模拟器进程流量转发给代理服务器，抓取模拟器进程的数据包。
	- 相关工具
		- http analyzer
		- Proxifier + burp/fiddler
+ 真机
	- 原理：电脑开启wifi热点（wifi共享大师），使用Proxifier设置代理，将流量转发到burp，这样手机端不用设置任何代理。
	- burp设置代理
	- 电脑开启wifi热点，手机连接热点
	- 全局代理：Proxifier设置代理服务器端口为burp监听的地址和端口,规则里面选择wifi共享大师进程。


hook方式
----------------------------------------
+ 原理：hook住APP的网络请求函数，打印出数据包。

抓包问题
----------------------------------------

不走代理
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 现象
	- 配置完全ok
	- burp中没有任何数据包
	- APP使用正常，网络正常
+ 可能原因：APP使用的网络库设置了不走传统代理
+ 解决方案：vpn/透明代理、hook方式绕过

HTTPS单向证书校验
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 现象：APP使用中网络请求失败，网络错误等。
+ 原理：校验了服务器证书，这样的话，burp代理的证书就会被APP拒绝，无法抓包。
+ 解决方案：
	- xposed模块：JustTrustMe、SSLUnpinning、SSLKillSwitch等，hook掉证书校验函数，绕过证书校验。
	- objection:  ``objection -N -n com.iflytek.aistudyclient.parentcontrol start -s "android sslpinning disable"``
	- frida脚本
		- ssl-pinning-bypass-with-frida-2026.js

HTTPS双向证书校验
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 现象：BURP可以抓到客户端发出的请求，但服务器没有响应，或者响应错误。
+ 原理：除了客户端会校验服务器证书外，服务器端会校验客户端的请求证书，burp的证书会被服务器检测出来。

非常规HTTPS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 原理：SSL的lib库是自己改过的，证券类的应用比较多。
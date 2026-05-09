文件解析漏洞
=====================================
+ 注册文件类型
	- ``ftype``
		查看系统注册的文件类型对应的程序
	- ``assoc``
		通过assoc命令查看扩展名对应的文件类型。
+ 工程文件
	- 恶意工程文件
		工程文件中是否含有js，py脚本等
	- zip slip漏洞
		::
		
			生成工具：https://github.com/usdAG/slipit
			如：./slipit evil.zap17.zip ncrypt.dll --depth 10 --prefix "Program Files\Siemens"
			注：可同时利用dll劫持达到本地执行。
	- 序列化漏洞
		很难遇到。
+ 其它文件
	- 图片，pdf等
+ Fuzz
	- afl
	- peach
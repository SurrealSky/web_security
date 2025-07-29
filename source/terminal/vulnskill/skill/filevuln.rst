文件解析漏洞
=====================================

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
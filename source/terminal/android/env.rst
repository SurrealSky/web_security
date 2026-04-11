环境检测（APP闪退）
========================================

环境检测
----------------------------------------
+ 购买真机：Google Pixel 系列
	- 要选择一个解锁了的版本，才能刷机。
	- 自行root刷机或让商家给刷一个新的系统（root，面具，lsposed）

root检测（Magisk）
----------------------------------------
+ Magisk版本：<=23
	+ 隐藏magisk应用
		- magisk设置中，启用"隐藏Magisk应用"功能
	+ magiskhide功能
		- magisk设置中，启用"MagiskHide"功能
		- 超级用户授权中，MagiskHide中选中对应的app
+ Magisk版本：>=24
	+ shamko
+ 特殊版本：Magisk Delta
	+ 该版本专门针对安全检测进行优化，能够更有效地隐藏root状态，防止被检测到。

框架检测
----------------------------------------
+ xposed/lsposed:魔改代码去除特征，再重新编译。
+ frida：魔改frida，frida-server去除特征，再重新编译（github项目：strongR-frida-android）。

设备指纹检测
----------------------------------------
+ 检测原理：APP会检测google系列设备型号，启动扫描系统安装的APP列表等（因为国内用户基本忽略不计）。
	- lsposed:抹机王

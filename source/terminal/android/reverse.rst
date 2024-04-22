逆向分析
========================================

业务方向
----------------------------------------
+ 重打包
	- 加壳脱壳
	- 二次修改/打包
	- 做插件，去广告，过会员vip等
+ 养号
	- 破设备指纹，破协议（x神算法），特别是各种sign
	- 薅羊毛（基于各大各平台推出的激励）
	- 刷流量（刷赞，刷评论）。
+ 自动化。
	- 抢单脚本，爬虫脚本
	- 或基于无障碍服务
	- 或基于协议脱机执行
+ 游戏外挂
	- 棋牌透视，游戏外挂，游戏运行脚本等。
+ App多开，
	- 虚拟技术（VA等）
	- 虚拟gps地址
	- 虚拟手机参数
+ 马甲包业务
	- 特别是海外Google play上的马甲包（需要反编译，修改，打包，加固，对抗政策审核）。 

静态分析
----------------------------------------

dex-jar
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ dex2jar工具： ``https://github.com/pxb1988/dex2jar``
+ jd-gui工具： ``https://github.com/java-decompiler/jd-gui``


dex-smali
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ dex2smali工具：``https://github.com/iBotPeaches/Apktool``
+ 命令
	::
	
		java -jar apktool.jar d *.apk

so-arm/x86
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ IDA分析

动态分析
----------------------------------------

DDMS日志分析
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

重打包
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ log插桩
+ 代码修改

动态插桩-xposed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 项目地址：https://github.com/rovo89/Xposed
+ 使用范围
	- 仅支持到安卓8
	- 已停止更新

动态插桩-EdXposed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 项目地址：https://github.com/ElderDrivers/EdXposedManager
+ 适用范围
	- 支持 **Android 8.0以上版本** 
	- 通过 **Magisk v19 或更高版本** 进行安装

动态插桩-VirtualXposed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 项目地址：https://github.com/android-hacker/VirtualXposed
+ 适用范围
	- 免root
	- 支持 **Android 5.0~10.0**

动态插桩-LSPosed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 项目地址：https://github.com/LSPosed/LSPosed
+ 适用范围
	- 免root
	- 支持 **Android 8.1 ~ 14**
	- 通过 **Magisk v24 或更高版本** 进行安装
+ 环境部署
	- Install Magisk v24+
	- Install Riru v26.1.7+
	- Download and install LSPosed in Magisk app
	- Reboot
	- Open LSPosed manager from notification

动态插桩-Cydia Substrate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 项目地址：http://www.cydiasubstrate.com/
+ 适用范围
	- 支持 **Android 2.3 ~ 4.3** 

动态插桩-frida
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 项目地址：https://github.com/frida/frida
+ 适用范围
	- 版本关系
		::
		
			Frida版本 	Android版本
			Frida 12.6.13 	Android 4.1 - 4.3
			Frida 12.7.0 	Android 4.4
			Frida 12.8.1 	Android 5.0 - 5.1
			Frida 12.9.7 	Android 6.0 - 6.0.1
			Frida 12.9.8 	Android 7.0 - 7.1
			Frida 12.10.4 	Android 8.0 - 8.1
			Frida 12.11.7 	Android 9
			Frida 12.12.0 	Android 10
			Frida 12.12.2 	Android 11

SSL Pinning绕过
----------------------------------------
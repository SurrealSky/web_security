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

adb shell
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 项目地址：https://dl.google.com/android/repository/platform-tools-latest-windows.zip
+ 常用命令
	- 手机进入 **开发者选项** ，打开 **usb调试** 
	- adb help：帮助
	- adb devices：查看连接设备
	- adb shell：进入设备shell
	- 建立链接
		::
		
			adb -d：如果同时连了usb，又开了模拟器，连接当前唯一通过usb连接的安卓设备
			adb -e shell：指定当前连接此电脑的唯一的一个模拟器
			adb -s <设备号> shell：当电脑插多台手机或模拟器时，指定一个设备号进行连接
			exit：退出
			adb kill-server：杀死当前adb服务，如果连不上设备时，杀掉重启。（没事不要用它）
			adb start-server：杀掉后重启
			5037：adb默认端口，如果该端口被占用，可以指定一个端口号，如下命令↓
			adb -p 6666 start-server：任意指定一个 adb shell 的端口
	- apk操作指令
		::
		
			adb shell pm list packages：列出当前设备/手机，所有的包名
			adb shell pm list packages -f：显示包和包相关联的文件(安装路径)
			adb shell pm list packages -d：显示禁用的包名
			adb shell pm list packages -e：显示当前启用的包名
			adb shell pm list packages -s：显示系统应用包名
			adb shell pm list packages -3：显示已安装第三方的包名
			adb shell pm list packages xxxx：加需要过滤的包名，如：xxx = taobao
			adb install <文件路径\apk>：将本地的apk软件安装到设备(手机)上。如手机外部安装需要密码，记得手机输入密码。
			adb install -r <文件路径\apk>：覆盖安装
			adb install -d <文件路径\apk>：允许降级覆盖安装
			adb install -g <文件路径\apk>：授权/获取权限，安装软件时把所有权限都打开
			adb uninstall <包名>：卸载该软件/app。
			注意：安装时安装的是apk，卸载时是包名，可以通过 adb shell pm list packages 查看需要卸载的包名
			adb shell pm uninstall -k <包名>：虽然把此应用卸载，但仍保存此应用的数据和缓存
			adb shell am force-stop <包名>：强制退出该应用/app
	- 文件操作
		::
		
			adb push <本地路径\文件或文件夹> <手机端路径>：把本地(pc机)的文件或文件夹复制到设备(手机)
			adb pull <设备路径> <本地路径>: 从 Android 设备上获取文件并保存到本地计算机上。
	- 日志命令
		::
		
			adb shell logcat -c：清理现有日志
			adb shell logcat -v time ：输出日志，信息输出在控制台
			adb shell logcat -v time > <存放路径\log.txt>：输出日志并保存在本地文件
			Ctrl+C：终止日志抓取
			adb shell logcat -v time *:E > <存放路径\log.txt>：打印级别为Error的信息
			日志的等级：
			-v：Verbse（明细）
			-d：Debug（调试）
			-i：Info（信息）
			-w：Warn（警告）
			-e：Error（错误）
			-f：Fatal（严重错误）
			抓取日志的步骤先输入命令启动日志，然后操作 App，复现 bug，再 ctrl+c 停止日志，分析本地保存的文件。
			：日志是记录手机系统在运行app时有什么异常的事件
			EXCEPTION
			也可以把更详细得Anr日志拉取出来：adb shell pull /data/anr/traces.txt <存放路径>
	- 系统操作指令
		::
		
			adb shell getprop ro.product.model：获取设备型号
			adb shell getprop ro.build.version.release：获取Android系统版本
			adb shell getprop ro.build.version.sdk
			adb shell getprop ro.build.version.security_patch
			adb shell getprop ro.build.description
			adb shell getprop ro.product.cpu.abi：查看cpu架构信息
			adb get-serialno：获取设备的序列号（设备号）
			adb shell wm size：获取设备屏幕分辨率
			adb shell screencap -p /sdcard/mms.png：屏幕截图
			adb shell screencap -p /sdcard/screenshot.png：屏幕截图
			adb shell cat /proc/meminfo：获取手机内存信息
			adb shell df：获取手机存储信息
			adb shell screenrecord <存放路径/xxx.mp4>：录屏，命名以.mp4结尾
			adb shell screenrecord --time-limit 10 <存放路径/xxx.mp4>：录屏时间为10秒

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
+ 环境部署
	- PC端安装python，frida-tools
	- 手机端abd push安装frida-server
	- 增加权限: chmod 777 frida-server
	- 执行./frida-server
	- 监听端口
		::
		
			adb forward tcp:27042 tcp:27042
			adb forward tcp:27043 tcp:27043
+ 常用命令
	- 查看APP包名：frida-ps -Uai
+ 
+ 通杀加密

SSL Pinning绕过
----------------------------------------
注册表漏洞
=====================================
在 Windows 桌面应用漏洞赏金（Bug Bounty）中，
注册表（Registry） 是挖掘 **本地权限提升 (LPE)** 和 **持久化 (Persistence)** 漏洞的核心战场。注册表配置不当通常被视为高价值漏洞，因为它们能让低权限用户在无需交互的情况下获得管理员或系统权限。

漏洞类型
--------------------------------------

注册表权限配置错误 (Registry ACL Misconfiguration)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 漏洞原理：如果 **高权限服务或进程** 读取的某个注册表项，被设置为“普通用户可写”（如 Everyone 或 Authenticated Users 拥有 Full Control 或 Write 权限），攻击者可以修改该项。
+ 挖掘目标
	- Image File Execution Options (IFEO)：修改特定 .exe 的 Debugger 键值。当目标应用启动时，系统会转而运行你指定的恶意程序。
	- 服务路径劫持：在 HKLM\SYSTEM\CurrentControlSet\Services\ 下，如果能修改某个 LocalSystem 服务的 ImagePath，即可实现权限提升。
	- COM 组件劫持：修改 HKCU\Software\Classes\CLSID 下的组件路径。许多系统进程会先检查 HKCU（用户权限）再检查 HKLM（系统权限），从而造成“混淆代理”攻击。 

自动启动项劫持 (Auto-run Hijacking)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 漏洞原理：如果安装程序在 HKLM（系统级自启）中设置了一个 **普通用户可修改** 的路径或键值，低权限用户可以将其替换为恶意脚本。
+ 关键键值
	- HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	- HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

未引用的搜索路径 (Unquoted Service Paths)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 漏洞原理：Windows 会尝试按顺序执行 C:\Program.exe。如果注册表中该路径未加引号且攻击者对 C:\ 有写权限，即可劫持。
+ 挖掘目标：HKLM\SYSTEM\CurrentControlSet\Services\ 下的 ImagePath 键值。

敏感信息泄露 (Sensitive Data Disclosure)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 漏洞原理：某些注册表项可能包含敏感信息（如密码、API 密钥）。如果这些项权限过宽，攻击者可以读取并利用这些信息。
+ 挖掘目标：检查 HKCU 或 HKLM 下软件厂商目录，看是否有明文存储的密码、API Key 或 Session Token。

协议处理程序漏洞 (Protocol Handler Vulnerabilities)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 挖掘目标： ``HKCR\<protocol>\shell\open\command``
+ 漏洞类型：如果桌面应用注册了自定义协议（如 my-app://），且注册表中的命令处理未对参数进行转义（如 %1 缺少引号），可能导致 远程代码执行 (RCE) 或 参数注入。

挖掘思路
--------------------------------------

发现“弱权限”写入（寻找 LPE 机会）
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 旨在寻找高权限进程（如 System、Administrator）写入了普通用户也能修改的注册表项。
	::
		
		Operation is RegSetValue
		Integrity is System 或 High (寻找高权限操作)
		Path contains:

			HKLM\SOFTWARE (尤其是第三方软件安装目录)
			HKLM\SYSTEM\CurrentControlSet\Services (服务路径)
			HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run (自启项)

+ 实战技巧：看到结果后，立即使用 accesschk.exe -kvu <注册表路径> 检查权限。如果普通用户有 W (Write) 权限，漏洞达成。

捕捉 COM 劫持（劫持应用逻辑）
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 许多应用在启动时会尝试读取 HKCU（当前用户）下的 COM 组件类 ID，如果找不到才去查 HKLM。
	::

		Operation is RegOpenKey
		Path contains CLSID
		Result is NAME NOT FOUND
+ 挖掘点：如果一个以 SYSTEM 权限运行的程序尝试打开 HKCU\Software\Classes\CLSID\{GUID} 但失败了，你可以创建该路径并指向你的恶意 DLL，实现权限提升。

协议处理程序参数注入（寻找 RCE）
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 针对通过浏览器唤起桌面端应用的场景。
	::

		Operation is RegQueryValue
		Path contains \shell\open\command
		Detail contains %1
+ 关注点：观察 %1 是否被双引号包裹（如 "...exe" "%1"）。如果没有引号，或者应用在处理 %1 传入的参数时存在缺陷，你可以通过 my-app:// 构造恶意的参数注入攻击。

Windows
========================================

认证方式
----------------------------------------

本地用户认证
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Windows 在进行本地登录认证时操作系统会使用用户输入的密码作为凭证去与系统中的密码进行对比验证。通过 ``winlogon.exe`` 接收用户输入传递至 ``lsass.exe`` 进行认证。

``winlogon.exe`` 用于在用户注销、重启、锁屏后显示登录界面。 ``lsass.exe`` 用于将明文密码变成NTLM Hash的形式与SAM数据库比较认证。

网络认证
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
用户在工作组环境下远程登录windows，通过随机数挑战/应答认证机制实现Net-NTLM Hash身份认证（NTLM Hash + 随机数）。

域内认证
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
登录到域内windows，采用Kerberos协议，此时必须要有可信的第三方作为KDC（Key Distribution Center）密钥分发中心。

相关术语
----------------------------------------

SAM
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
安全帐户管理器(Security Accounts Manager，SAM) 是Windows操作系统管理用户帐户的安全所使用的一种机制。用来存储Windows操作系统密码的数据库文件为了避免明文密码泄漏SAM文件中保存的是明文密码在经过一系列算法处理过的 Hash值被保存的Hash分为LM Hash、NTLM Hash。当用户进行身份认证时会将输入的Hash值与SAM文件中保存的Hash值进行对比。

SAM文件保存于 ``%SystemRoot%\system32\config\sam`` 中，在注册表中保存在 ``HKEY_LOCAL_MACHINE\SAM\SAM`` ， ``HKEY_LOCAL_MACHINE\SECURITY\SAM`` 。 在正常情况下 SAM 文件处于锁定状态不可直接访问、复制、移动仅有 system 用户权限才可以读写该文件。

HASH格式
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
::

	Administrator:500:AAD3B435B51404EEAAD3B435B51404EE:31D6CFE0D16AE931B73C59D7E0C089C0::: 

	其中AAD3B435B51404EEAAD3B435B51404EE是LM Hash而31D6CFE0D16AE931B73C59D7E0C089C0是NTLM Hash。

LM Hash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
LM Hash(LAN Manager Hash) 是windows最早用的加密算法，由IBM设计。LM Hash 使用硬编码秘钥的DES，且存在缺陷。早期的Windows系统如XP、Server 2003等使用LM Hash，而后的系统默认禁用了LM Hash并使用NTLM Hash。

在LM Hash中，用户的密码会转换为大写，最长14字节，不足14字节则需要在其后添加0×00补足14字节。而后将14字节分为两段7字节的密码，通过处理得到两组8字节数据。而后以 ``KGS!@#$%`` 作为秘钥对这两组数据进行标准DES加密，拼接后得到最后的LM Hash。

NT Hash/NTLM
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
为了解决LM Hash的安全问题，微软于1993年在Windows NT 3.1中引入了NTLM协议。将密码统一转换为unicode编码后计算md4 Hash，得到NT Hash。

从Windows Vista 和 Windows Server 2008开始，默认情况下只存储NTLM Hash，LM Hash将不再存在。

如果空密码或者不储蓄LM Hash的话，一般抓到的LM Hash是AAD3B435B51404EEAAD3B435B51404EE（win7）这里的LM Hash并没有价值


Kerberos认证过程
----------------------------------------
+ AS-REQClient 向 KDC 发起请求明文密码将会被加密为 hash时间戳使用 Client hash 进行加密然后作为认证票据TGT请求AS-REQ中的认证因子发送给KDC。
+ AS-REPKDC 使用 Client hash 进行解密如果结果正确就返回用 krbtgt hash 加密的 TGT 票据。TGT 里面包含 PACPAC 包含 Client 的 sidClient 所在的组。
+ TGS-REQ当 Client 请求票据授予服务TGS票据时用户需要向 KDC 展示TGT数据。KDC 会打开票据进行校验和检查。如果 KDC 能够打开票据并能通过校验和检查那么会认为 TGT 为有效票据。此时 TGT 中的数据会被复制以创建 TGS 票据。
+ TGS-REPKDC 使用目标服务账户的 hash 对 TGS 票据进行加密然后将结果发送给 Client。(这一步不管用户有没有访问服务的权限只要TGT 正确就返回 TGS 票据)
+ AP-REQClient 访问目标服务并发送 TGS 票据去请求服务。
+ AP-REP服务使用自己的 hash 解密 TGS 票据。如果解密正确就拿着 PAC 去 KDC 查询 Client 有没有访问权限KDC 解密 PAC。获取 Client的 sid以及所在的组再根据该服务的 ACL判断 Client 是否有访问服务的权限。

参考链接
----------------------------------------
- `Windows身份认证及利用思路 <https://www.freebuf.com/articles/system/224171.html>`_

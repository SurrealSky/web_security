渗透测试经验分享
========================================

漏洞平台思路
----------------------------------------
- 注册账号
	| 补天、漏洞盒子等。
- 挖掘公益SRC
	| 公益SRC是白帽子随机发现的漏洞提交漏洞盒子平台，平台对漏洞审核后通知企业认领。厂商注册公益SRC成功后即可认领漏洞，公益SRC服务不收取企业任何费用。
- 步骤
	- 网站语言、操作系统、数据库版本
	- 网站有没有用CMS
	- 可能存在的漏洞
	- 确定登录页面

思路2
----------------------------------------
- Google Hacking
	- 收集网站登录页面
	- 弱密钥

思路3
----------------------------------------
- 批量识别网站CMS
	- 低版本进行NDAY攻击

通用型漏洞挖掘
-----------------------------------------
- 发现通用型漏洞
	- 自己发掘站点通用型漏洞
	- 根据cvnd等公布的漏洞进行环境搭建和浮现
- 编写POC
- 挖掘漏洞站点
	- 漏洞站点包含的链接，url特征
	- fofa等站点搜索相似站点
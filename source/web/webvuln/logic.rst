逻辑漏洞 / 业务漏洞
================================

简介
--------------------------------
逻辑漏洞是指由于程序逻辑不严导致一些逻辑分支处理错误造成的漏洞。一般自动化漏洞扫描器是无法扫描出此类漏洞，只能通过手工的渗透测试去检查。

安装逻辑
--------------------------------
- 查看能否绕过判定重新安装
- 查看能否利用安装文件获取信息
- 看能否利用更新功能获取信息

交易
--------------------------------

购买
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 修改支付的价格
	::
	
		（1）利用拦截发包协议修改支付价格。
		（2）利用第三方支付金额的数字漏洞如下：
		支付0.019的订单，第三方支付不支持"厘"，就可能支付的金额是0.01（也有可能是0.02）
		这样，当你用第三方支付或者充值了0.01，购买了0.019的订单。
		（3）1元购
		支付金额为2147483648时，第三方充值的金额是int的话，就会溢出变成1元。

- 修改支付的状态
- 修改购买数量为负数
- 修改金额为负数
- 重放成功的请求
- 并发数据库锁处理不当

签约漏洞
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 新会员充值优惠
	::
	
		A手机登录，首次签约，优惠支付，跳到支付界面。
		B手机登录，首次签约，优惠支付，跳到支付界面。
		A手机进行支付。
		B手机进行支付。
		存在漏洞的话，那么会进行了两次优惠支付，如对应会员期限为两倍。
- 会员升级
	::
	
		场景类似会员充值优惠利用。
- 优惠卷支付
	::
	
		A手机登录，优惠券支付，跳到支付界面。
		B手机登录，关闭这个订单，重新使用优惠券创建一个订单。
		A手机上把未支付的订单支付完成，关闭的订单可能会进入发货阶段。

业务风控
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 刷优惠券
- 套现

账户
--------------------------------

注册
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 覆盖注册
- 尝试重复用户名
- 注册遍历猜解已有账号

邮箱用户名
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 前后空格
- 大小写变换

手机号用户名
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 前后空格
- +86

登录
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 撞库
- 账号劫持
- 恶意尝试帐号密码锁死账户

找回密码
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 重置任意用户密码
- 密码重置后新密码在返回包中
- Token验证逻辑在前端
- X-Forwarded-Host处理不正确

修改密码
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 越权修改密码
- 修改密码没有旧密码验证

申诉
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 身份伪造
- 逻辑绕过

2FA
--------------------------------
- 重置密码后自动登录没有2FA
- OAuth登录没有启用2FA
- 2FA可爆破
- 2FA有条件竞争
- 修改返回值绕过
- 激活链接没有启用2FA
- 可通过CSRF禁用2FA

验证码
--------------------------------
- 验证码可重用
- 验证码可预测
- 验证码强度不够
- 验证码无时间限制或者失效时间长
- 验证码无猜测次数限制
- 验证码传递特殊的参数或不传递参数绕过
- 验证码可从返回包中直接获取
- 验证码不刷新或无效
- 验证码数量有限
- 验证码在数据包中返回
- 修改Cookie绕过
- 修改返回包绕过
- 验证码在客户端生成或校验
- 验证码可OCR或使用机器学习识别
- 验证码用于手机短信/邮箱轰炸

Session
--------------------------------
- Session机制
- Session猜测 / 爆破
- Session伪造
- Session泄漏
- Session Fixation

越权
--------------------------------
- 水平越权
	+ 即：攻击者可以访问与他拥有相同权限的用户的资源 
	+ 利用方式：权限类型不变，通过修改数据包中的用户ID等
	+ 利用场景：一般越权漏洞容易出现在权限页面(需要登陆的页面)增，删，改，查的地方。
- 垂直越权
	+ 即：低级别攻击者可以访问高级别用户的资源
	+ 利用方式：权限ID不变，通过修改数据包中的用户权限类型等
	+ 利用场景：一般越权漏洞容易出现在权限页面(需要登陆的页面)增，删，改，查的地方。
- 交叉越权
	- 利用方式：修改用户ID等，修改权限类型等

随机数安全
--------------------------------
- 使用不安全的随机数发生器
- 使用时间等易猜解的因素作为随机数种子

其他
--------------------------------
- 用户/订单/优惠券等ID生成有规律，可枚举
- 接口无权限、次数限制
- 加密算法实现误用
- 执行顺序
- 敏感信息泄露

参考链接
--------------------------------
- `水平越权漏洞及其解决方案 <http://blog.csdn.net/mylutte/article/details/50819146#10006-weixin-1-52626-6b3bffd01fdde4900130bc5a2751b6d1>`_
- `细说验证码安全 测试思路大梳理 <https://xz.aliyun.com/t/6029>`_

越权
================================

简介
--------------------------------
越权漏洞一般分为垂直越权和水平越权。


相关参数
--------------------------------
+ ``product_id，user_id，address_id``

越权方法
--------------------------------

restful api接口
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 正常请求： ``PUT /api/users/current/profile/email HTTP/2``
+ 越权请求
	- ``PUT /api/users/1/profile/email HTTP/2``
	- ``PUT /api/users/current/../1/profile/email HTTP/2``

修改注册审核参数
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    - 个人信息中包含类似status的字段，可能存在注册审核的逻辑漏洞。
    - 注册添加payload： ``{"username":"","password":"","status":"approved"}``，查看是否可以绕过审核。

隐藏参数
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- ``GET /api/users/profile HTTP/2`` => ``GET /api/users/profile?user_id=1 HTTP/2``

特殊构造
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- ./..
	- 如： ``http://localhost:4242/checkout-session?sessionId=a14L46PUF4tbXhcFrVU4Zv42kBQD2HW5TIR6XdNHPJFc`` => ``http://localhost:4242/checkout-session?sessionId=.``
- 结合绕过
	- 如: ``GET /api/users/123 HTTP/2`` => ``GET /api/users/123/ HTTP/2``
	- 其它： ``%20 %09 %0b % 0c %1c %1d %1e %1f`` (fuzz ``%00->%ff`` ) 等

双写
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- ``GET /api/users?user_id=1&user_id=2 HTTP/2``
- ``{"user_id":"1","user_id":"2"}``
- ``{"user_id":["1","2"]}`` 
- 对象嵌套
	::

		"user_id":{
			"user_id":"1"
		}


参考链接
--------------------------------
- `水平越权漏洞及其解决方案 <http://blog.csdn.net/mylutte/article/details/50819146#10006-weixin-1-52626-6b3bffd01fdde4900130bc5a2751b6d1>`_
- `细说验证码安全 测试思路大梳理 <https://xz.aliyun.com/t/6029>`_

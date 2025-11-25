安全防护
================================

SOP
--------------------------------

简介
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
同源策略（Same Origin Policy，SOP）是浏览器的一种安全机制，用于防止不同源的网页相互访问和操作，从而保护用户的数据安全。SOP规定，只有当两个网页具有相同的协议、域名和端口时，它们才能相互访问。

访问策略
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
同源策略控制了不同源之间的交互，这些交互通常分为三类：

+ 通常允许跨域写操作（Cross-origin writes）
    + 链接（links）
    + 重定向
    + 表单提交
+ 通常允许跨域资源嵌入（Cross-origin embedding）
+ 通常不允许跨域读操作（Cross-origin reads）

可能嵌入跨源的资源的一些示例有：

+ ``<script src="..."></script>`` 标签嵌入跨域脚本。语法错误信息只能在同源脚本中捕捉到。
+ ``<link rel="stylesheet" href="...">`` 标签嵌入CSS。由于CSS的松散的语法规则，CSS的跨域需要一个设置正确的Content-Type 消息头。
+ ``<img>`` / ``<video>`` / ``<audio>`` 嵌入多媒体资源。
+ ``<object>`` ``<embed>`` 和 ``<applet>`` 的插件。
+ ``@font-face`` 引入的字体。一些浏览器允许跨域字体（ cross-origin fonts），一些需要同源字体（same-origin fonts）。
+ ``<frame>`` 和 ``<iframe>`` 载入的任何资源。站点可以使用X-Frame-Options消息头来阻止这种形式的跨域交互。

JSONP跨域：利用 ``<script>`` 标签的跨域能力实现跨域数据的访问，请求动态生成的JavaScript脚本同时带一个callback函数名作为参数。

服务端收到请求后，动态生成脚本产生数据，并在代码中以产生的数据为参数调用callback函数。

JSONP也存在一些安全问题，例如当对传入/传回参数没有做校验就直接执行返回的时候，会造成XSS问题。没有做Referer或Token校验就给出数据的时候，可能会造成数据泄露。

另外JSONP在没有设置callback函数的白名单情况下，可以合法的做一些设计之外的函数调用，引入问题。这种攻击也被称为SOME攻击。

CORS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
CORS是一个W3C标准，全称是"跨域资源共享"（Cross-origin resource sharing）。通过这个标准，可以允许浏览器读取跨域的资源。

常见请求头：

- Origin
    - 预检请求或实际请求的源站URI, 浏览器请求默认会发送该字段
    - ``Origin: <origin>``
- Access-Control-Request-Method
    - 声明请求使用的方法
    - ``Access-Control-Request-Method: <method>``
- Access-Control-Request-Headers
    - 声明请求使用的header字段
    - ``Access-Control-Request-Headers: <field-name>[, <field-name>]*``

常见返回头：

- Access-Control-Allow-Origin
    - 声明允许访问的源外域URI
    - 对于携带身份凭证的请求不可使用通配符 ``*``
    - ``Access-Control-Allow-Origin: <origin> | *``
- Access-Control-Expose-Headers
    - 声明允许暴露的头
    - e.g. ``Access-Control-Expose-Headers: X-My-Custom-Header, X-Another-Custom-Header``
- Access-Control-Max-Age
    - 声明Cache时间
    - ``Access-Control-Max-Age: <delta-seconds>``
- Access-Control-Allow-Credentials
    - 声明是否允许在请求中带入
    - ``Access-Control-Allow-Credentials: true``
- Access-Control-Allow-Methods
    - 声明允许的访问方式
    - ``Access-Control-Allow-Methods: <method>[, <method>]*``
- Access-Control-Allow-Headers
    - 声明允许的头
    - ``Access-Control-Allow-Headers: <field-name>[, <field-name>]*``

CSP
--------------------------------

CSP是什么？
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Content Security Policy，简称 CSP。顾名思义，这个规范与内容安全有关，主要是用来定义页面可以加载哪些资源，减少 XSS 的发生。

配置
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

CSP策略可以通过 HTTP 头信息或者 meta 元素定义。

CSP 有三类：

- Content-Security-Policy  (Google Chrome)
- X-Content-Security-Policy (Firefox)
- X-WebKit-CSP (WebKit-based browsers, e.g. Safari)

::

    HTTP header :
    "Content-Security-Policy:" 策略
    "Content-Security-Policy-Report-Only:" 策略


HTTP Content-Security-Policy 头可以指定一个或多个资源是安全的，而Content-Security-Policy-Report-Only则是允许服务器检查（非强制）一个策略。多个头的策略定义由优先采用最先定义的。

HTML Meta :
::

    <meta http-equiv="content-security-policy" content="策略">
    <meta http-equiv="content-security-policy-report-only" content="策略">


指令说明
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

============    ============
指令            说明     
============    ============
default-src     定义资源默认加载策略
connect-src     定义 Ajax、WebSocket 等加载策略
font-src        定义 Font 加载策略
frame-src       定义 Frame 加载策略
img-src         定义图片加载策略
media-src       定义 <audio>、<video> 等引用资源加载策略
object-src      定义 <applet>、<embed>、<object> 等引用资源加载策略
script-src      定义 JS 加载策略
style-src       定义 CSS 加载策略
base-uri        定义 <base> 根URL策略，不使用default-src作为默认值
sandbox         值为 allow-forms，对资源启用 sandbox
report-uri      值为 /report-uri，提交日志
============    ============

关键字
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- ``-``
    - 允许从任意url加载，除了 ``data:`` ``blob:`` ``filesystem:`` ``schemes``
    - e.g. ``img-src -``
- ``none``
    - 禁止从任何url加载资源
    - e.g. ``object-src 'none'``
- ``self``
    - 只可以加载同源资源
    - e.g. ``img-src 'self'``
- ``data:``
    - 可以通过data协议加载资源
    - e.g. ``img-src 'self' data:``
- ``domain.example.com``
    - e.g. ``img-src domain.example.com``
    - 只可以从特定的域加载资源
- ``\*.example.com``
    - e.g. ``img-src \*.example.com``
    - 可以从任意example.com的子域处加载资源
- ``https://cdn.com``
    - e.g. ``img-src https://cdn.com``
    - 只能从给定的域用https加载资源
- ``https:``
    - e.g. ``img-src https:``
    - 只能从任意域用https加载资源
- ``unsafe-inline``
    - 允许内部资源执行代码例如style attribute,onclick或者是sicript标签
    - e.g. ``script-src 'unsafe-inline'``
- ``unsafe-eval``
    - 允许一些不安全的代码执行方式，例如js的eval()
    - e.g. ``script-src 'unsafe-eval'``
- ``nonce-<base64-value>'``
    - 使用随机的nonce，允许加载标签上nonce属性匹配的标签
    - e.g. ``script-src 'nonce-bm9uY2U='``
- ``<hash-algo>-<base64-value>'``
    - 允许hash值匹配的代码块被执行
    - e.g. ``script-src 'sha256-<base64-value>'``

配置范例
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

允许执行内联 JS 代码，但不允许加载外部资源
::

    Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline';


Bypass
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

预加载：浏览器为了增强用户体验，让浏览器更有效率，就有一个预加载的功能，大体是利用浏览器空闲时间去加载指定的内容，然后缓存起来。这个技术又细分为DNS-prefetch、subresource、prefetch、preconnect、prerender。

HTML5页面预加载是用link标签的rel属性来指定的。如果csp头有unsafe-inline，则用预加载的方式可以向外界发出请求，例如

::

    <!-- 预加载某个页面 -->
    <link rel='prefetch' href='http://xxxx'><!-- firefox -->
    <link rel='prerender' href='http://xxxx'><!-- chrome -->
    <!-- 预加载某个图片 -->
    <link rel='prefetch' href='http://xxxx/x.jpg'>
    <!-- DNS 预解析 -->
    <link rel="dns-prefetch" href="http://xxxx">
    <!-- 特定文件类型预加载 -->
    <link rel='preload' href='//xxxxx/xx.js'><!-- chrome -->

另外，不是所有的页面都能够被预加载，当资源类型如下时，讲阻止预加载操作：

- URL中包含下载资源
- 页面中包含音频、视频
- POST、PUT和DELET操作的ajax请求
- HTTP认证
- HTTPS页面
- 含恶意软件的页面
- 弹窗页面
- 占用资源很多的页面
- 打开了chrome developer tools开发工具

+ MIME Sniff
   举例来说，csp禁止跨站读取脚本，但是可以跨站读img，那么传一个含有脚本的img，再``<script href='http://xxx.com/xx.jpg'>``，这里csp认为是一个img，绕过了检查，如果网站没有回正确的mime type，浏览器会进行猜测，就可能加载该img作为脚本


+ 302跳转
   对于302跳转绕过CSP而言，实际上有以下几点限制：

   - 跳板必须在允许的域内。
   - 要加载的文件的host部分必须跟允许的域的host部分一致

+ iframe
   当可以执行代码时，可以创建一个源为 ``css`` ``js`` 等静态文件的frame，在配置不当时，该frame并不存在csp，则在该frame下再次创建frame，达到bypass的目的。同理，使用 ``../../../`` ``/%2e%2e%2f`` 等可能触发服务器报错的链接也可以到达相应的目的。

应用层保护
--------------------------------

HTML过滤
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 输入过滤
- 输出过滤
- 黑名单白名单
	使用一些白名单或者黑名单来过滤用户输入的HTML，以实现过滤的效果。例如DOMPurify等工具都是用该方式实现了XSS的保护。

X-Frame
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
X-Frame-Options 响应头有三个可选的值：

- DENY
    - 页面不能被嵌入到任何iframe或frame中
- SAMEORIGIN
    - 页面只能被本站页面嵌入到iframe或者frame中
- ALLOW-FROM
    - 页面允许frame或frame加载

XSS保护头
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
基于 Webkit 内核的浏览器（比如Chrome）有一个名为XSS auditor的防护机制，如果浏览器检测到了含有恶意代码的输入被呈现在HTML文档中，那么这段呈现的恶意代码要么被删除，要么被转义，恶意代码不会被正常的渲染出来。

而浏览器是否要拦截这段恶意代码取决于浏览器的XSS防护设置。

要设置浏览器的防护机制，则可使用X-XSS-Protection字段
该字段有三个可选的值

::

    0: 表示关闭浏览器的XSS防护机制

    1: 删除检测到的恶意代码， 如果响应报文中没有看到X-XSS-Protection 字段，那么浏览器就认为X-XSS-Protection配置为1，这是浏览器的默认设置

    1; mode=block: 如果检测到恶意代码，在不渲染恶意代码

FireFox没有相关的保护机制，如果需要保护，可使用NoScript等相关插件。

防御DOM-Based XSS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- 避免客户端文档重写，重定向和其它敏感操作
- 分析和强化客户端javascript代码（Dom对象）

其它防御方式
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Anti_XSS调用库

::

	AntiXss类库是一款预防注入攻击的开源类库，它通过白名单机制进行内容编码。
	目前它支持这些输入类型：XML，HTML，QueryString，HTMLFormURLEncode，Ldap，JavaScript。
	在日常的开发中我们并不会安全编码像Ldap或JavaScript这样的输入类型，大多都是对XML，QueryString或Form URL进行安全编码。

- HttpOnly Cookie

::

	如果在cookie中设置了HttpOnly属性，那么通过js脚本将无法读取或修改cookie信息。
	
- WAF
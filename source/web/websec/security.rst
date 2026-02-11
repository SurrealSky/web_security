安全策略 
================================

SOP
--------------------------------
+ 同源策略（Same Origin Policy，SOP）：  **浏览器** 的一种安全机制，用于防止不同源的网页脚本相互访问和操作，从而保护用户的数据安全。SOP规定，只有当两个网页具有相同的协议、域名和端口时，它们才能相互访问。
+ 嵌入跨源的资源示例：
    - ``<script src="..."></script>`` 标签嵌入跨域脚本。语法错误信息只能在同源脚本中捕捉到。
    - ``<link rel="stylesheet" href="...">`` 标签嵌入CSS。由于CSS的松散的语法规则，CSS的跨域需要一个设置正确的Content-Type 消息头。
    - ``<img>`` / ``<video>`` / ``<audio>`` 嵌入多媒体资源。
    - ``<object>`` ``<embed>`` 和 ``<applet>`` 的插件。
    - ``@font-face`` 引入的字体。一些浏览器允许跨域字体（ cross-origin fonts），一些需要同源字体（same-origin fonts）。
    - ``<frame>`` 和 ``<iframe>`` 载入的任何资源。站点可以使用X-Frame-Options消息头来阻止这种形式的跨域交互。
+ 缺点
    - 过于严格：正当的跨域需求也被禁止了（比如前端 app.com 想调用后端 api.com）
    - 漏洞依然存在：虽然不能直接读数据，但可以发起请求（只是看不到响应）
+ JSONP跨域
    - 利用 ``<script>`` 标签的跨域能力实现跨域数据的访问，只能发起 **GET请求** ，动态生成的JavaScript脚本同时带一个 **callback函数** 名作为参数。
    - 服务端收到请求后，动态生成脚本产生数据，并在代码中以产生的数据为参数调用callback函数。
+ 常见攻击
    - xss： SOP保护的是源与源之间，但对同源内的恶意代码无能为力。
    - CSRF： SOP允许跨域发送请求并携带Cookie，只是不允许读取响应。
    - jsonp xss：当对传入/传回参数没有做校验就直接执行返回的时候，会造成XSS问题。没有做Referer或Token校验就给出数据的时候，可能会造成数据泄露。
    - SOME攻击：没有设置callback函数的白名单情况下，可以合法的做一些设计之外的函数调用，引入问题。
    - 点击劫持：利用iframe嵌套不同源的页面，诱导用户点击。SOP允许嵌入跨域的iframe，只是不允许交互。但视觉欺骗足以完成攻击。
        ::

            <iframe src="https://bank.com/delete-account" 
                style="opacity:0; position:absolute; top:0; left:0;">
            </iframe>
            <button style="position:absolute; top:0; left:0;">
                点击抽奖！ <!-- 用户实际点的是银行iframe -->
            </button>
+ 安全对抗
    - 对抗CSRF
        - 验证码
        - Token验证：实现复杂，需要在所有表单和AJAX请求中添加。
        - Referer验证: 只能防御站外类型的CSRF攻击。
    - 对抗点击劫持
        - X-Frame-Options头
            - DENY
                - 页面不能被嵌入到任何iframe或frame中
            - SAMEORIGIN
                - 页面只能被本站页面嵌入到iframe或者frame中
            - ALLOW-FROM
                - 页面允许frame或frame加载
    - 对抗XSS
        - 输入过滤
        - HttpOnly：Cookie可以带，但你不能用JavaScript读它，即使XSS成功，也无法读取cookie。

CORS
--------------------------------
+ 背景： **SOP过于严格** ，无法满足现代Web应用的需求，尤其是在 **前后端分离** 的架构中， **前端需要与不同域的后端API** 进行交互。
+ 介绍：CORS是一个W3C标准，全称是"跨域资源共享"（Cross-origin resource sharing）。它是 **服务端** 通过控制响应头部来控制是否允许浏览器进行一些跨域请求。
+ 原理
    - 预检请求：对于复杂操作，先问“能不能做”
    - 凭据控制：明确声明是否发送Cookie
+ 常见请求头：
    - Origin
        - 预检请求或实际请求的源站URI, 浏览器请求默认会发送该字段
        - ``Origin: <origin>``
    - Access-Control-Request-Method
        - 声明请求使用的方法
        - ``Access-Control-Request-Method: <method>``
    - Access-Control-Request-Headers
        - 声明请求使用的header字段
        - ``Access-Control-Request-Headers: <field-name>[, <field-name>]*``
+ 常见返回头
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
+ 背景：XSS攻击依然频繁发生，传统的防御手段（输入过滤、输出编码等）容易被绕过，难以完全防御XSS攻击。
+ 介绍：Content Security Policy，简称 CSP，主要是用来定义页面可以加载哪些资源，减少 XSS 的发生。
+ 根本性变化：从“检测恶意内容”到“定义合法来源”，即使被注入恶意脚本，只要来源不在白名单，浏览器就不执行。
+ CSP策略可以通过 HTTP 头信息或者 meta 元素定义，有三类：
    - Content-Security-Policy  (Google Chrome)： 可以指定一个或多个资源是安全的
    - X-Content-Security-Policy (Firefox) ：允许服务器检查（非强制）一个策略
    - X-WebKit-CSP (WebKit-based browsers, e.g. Safari)
    - HTML Meta :
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

Bypass
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 预加载：
    - 浏览器为了增强用户体验，让浏览器更有效率，就有一个预加载的功能，大体是利用浏览器空闲时间去加载指定的内容，然后缓存起来。这个技术又细分为DNS-prefetch、subresource、prefetch、preconnect、prerender。
    - HTML5页面预加载是用link标签的rel属性来指定的。如果csp头有unsafe-inline，则用预加载的方式可以向外界发出请求。
+ MIME Sniff
    - 举例来说，csp禁止跨站读取脚本，但是可以跨站读img，那么传一个含有脚本的img，再``<script href='http://xxx.com/xx.jpg'>``，这里csp认为是一个img，绕过了检查，如果网站没有回正确的mime type，浏览器会进行猜测，就可能加载该img作为脚本
+ 302跳转
    - 跳板必须在允许的域内。
    - 要加载的文件的host部分必须跟允许的域的host部分一致
+ iframe
    - 当可以执行代码时，可以创建一个源为 ``css`` ``js`` 等静态文件的frame，在配置不当时，该frame并不存在csp，则在该frame下再次创建frame，达到bypass的目的。同理，使用 ``../../../`` ``/%2e%2e%2f`` 等可能触发服务器报错的链接也可以到达相应的目的。

cookie进化
----------------------------------
+ Secure: 只通过HTTPS传输
+ SameSite 是 Cookie 的一个属性，用于控制浏览器是否在跨站（cross-site）请求中发送 Cookie。
+ SameSite=Strict（最严格）
    - 完全禁止跨站携带 Cookie
    - 只有同站（same-site） 请求才发送
    - 用户从外部链接点击进入时，Cookie 不会被发送。
+ SameSite=Lax（宽松，Chrome 80+ 默认值）
    - 允许顶级导航的 GET 请求跨站携带 Cookie
    - 阻止跨站的 POST、PUT、DELETE 等非安全方法的请求携带 Cookie
    - 阻止 <img>、<script>、<iframe> 等子资源请求携带 Cookie
+ SameSite=None（无限制）
    - 允许所有跨站请求携带 Cookie
    - 必须同时设置 Secure 属性（即必须使用 HTTPS）


XSS保护头
----------------------------------
基于 Webkit 内核的浏览器（比如Chrome）有一个名为XSS auditor的防护机制，如果浏览器检测到了含有恶意代码的输入被呈现在HTML文档中，那么这段呈现的恶意代码要么被删除，要么被转义，恶意代码不会被正常的渲染出来。

而浏览器是否要拦截这段恶意代码取决于浏览器的XSS防护设置。

要设置浏览器的防护机制，则可使用X-XSS-Protection字段
该字段有三个可选的值

::

    0: 表示关闭浏览器的XSS防护机制

    1: 删除检测到的恶意代码， 如果响应报文中没有看到X-XSS-Protection 字段，那么浏览器就认为X-XSS-Protection配置为1，这是浏览器的默认设置

    1; mode=block: 如果检测到恶意代码，在不渲染恶意代码

FireFox没有相关的保护机制，如果需要保护，可使用NoScript等相关插件。

其它防御方式
----------------------------------

- Anti_XSS调用库

::

	AntiXss类库是一款预防注入攻击的开源类库，它通过白名单机制进行内容编码。
	目前它支持这些输入类型：XML，HTML，QueryString，HTMLFormURLEncode，Ldap，JavaScript。
	在日常的开发中我们并不会安全编码像Ldap或JavaScript这样的输入类型，大多都是对XML，QueryString或Form URL进行安全编码。

- HttpOnly Cookie

::

	如果在cookie中设置了HttpOnly属性，那么通过js脚本将无法读取或修改cookie信息。
	
- WAF
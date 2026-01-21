Web缓存中毒漏洞
======================================

概念
--------------------------------------
Web缓存中毒（Web Cache Poisoning）是一种攻击技术，攻击者通过向Web缓存注入恶意内容，使得后续访问该缓存的用户接收到被篡改的响应。这种攻击通常利用了Web缓存系统对HTTP请求和响应的处理方式，诱使缓存存储恶意数据，从而影响其他用户的浏览体验或窃取敏感信息。

本质
--------------------------------------
由非缓存键导致的差异化响应都能够被存储并提供给其他用户

基础
--------------------------------------
+ 缓存： 通常通过CDN、负载均衡器或简单的方向代理来实现。
+ 缓存键（cache key）
    - 通过缓存键来判断两个请求是否正在尝试加载相同的资源。
    - 决定 “是否命中缓存”。两个请求的缓存键完全相同，才可能返回同一个缓存响应。
    - 常见成员：HTTP方法 (GET/POST)、URL路径 (如/index.php)、查询字符串 (?key=value)、Host头等。
+ 非缓存键
    - 请求中不参与生成缓存标识符的其他部分。
    - 对缓存查找无影响，但可能被后端应用读取并用于生成不同的响应内容。
    - 常见成员：许多HTTP请求头，如 User-Agent, Referer, X-Forwarded-For, X-Original-URL、以及某些Cookie或POST数据。
+ X-Forward-For：表示代理前的原始IP
    - XFF：在客户端访问服务器的过程中如果需要经过HTTP代理或者负载均衡服务器,可以被用来获取最初发起请求的客户端的IP地址，这个消息首部成为事实上的标准。
+ X-Forward-Host：表示原始的URL请求地址
    - XFH：是一个事实上的标准首部,用来确定客户端发起的请求中使用Host指定的初始域名。
+ X-Forward-proto/scheme：表示当前请求以http/https的方式
    - XFP：是一个事实上的标准首部，用来确定客户端与代理服务器或者负载均衡服务器之间的连接所采用的传输协议（HTTP 或 HTTPS）。
+ Via：代理服务器在转发时添加，作为标记。
    - Via 是一个通用首部，是由代理服务器添加的，适用于正向和反向代理，在请求和响应首部中均可出现。
+ Vary：赋予的值代表缓存键
    - Vary 是一个HTTP响应头部信息，它决定了对于未来的一个请求头，应该用一个缓存的回复(response)还是向源服务器请求一个新的回复。
+ Cache-Control：缓存机制。
    - 当值为no-store时表示缓存中不得存储任何关于客户端请求和服务端响应的内容。每次由客户端发起的请求都会下载完整的响应内容。
    - 当值为no-cache时表示每次有请求发出时，缓存会将此请求发到服务器（译者注：该请求应该会带有与本地缓存相关的验证字段），服务器端会验证请求中所描述的缓存是否过期，若未过期（注：实际就是返回304），则缓存才使用本地缓存副本。
    - 当值为public时表示该响应可以被任何中间人（译者注：比如中间代理、CDN等）缓存。
    - 当值为private则表示该响应是专用于某单个用户的，中间人不能缓存此响应，该响应只能应用于浏览器私有缓存中。
    - max-age=<seconds>表示资源能够被缓存（保持新鲜）的最大时间。
+ X-Original-URL/X-Rewrite-URL：对这些报头的支持允许用户通过X-Original-URL或X-Rewrite-URL HTTP请求报头重写请求URL中的路径，并允许用户访问一个URL，但web应用程序返回一个不同的URL，这可以绕过对更高级别缓存和web服务器的限制。


漏洞利用
--------------------------------------

漏洞来源
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
攻击者操纵 **非缓存键** 来“欺骗”后端产生恶意响应，而这个响应又因缓存键相同被错误缓存。

测试筛选
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 目标有缓存吗？
    - 检查响应头中是否有 **X-Cache、CF-Cache-Status、Age、Cache-Control（值不是 no-store, private）** 等指示缓存的头部。
    - 短时间内连续请求两次，对比响应头的 Age 值是否增长，或观察 X-Cache 是否从 MISS 变为 HIT。
+ 目标有用户交互/输入吗？
    - 动态内容：页面是否包含用户数据（如“欢迎，[用户名]”）、搜索框、筛选器、多语言切换等。
    - 参数化URL：URL中是否有 ?id=、?lang=、?ref= 等查询参数。这些是关键测试点。
+ 目标重要吗？
    - 高价值目标：登录入口、首页、用户中心、API接口、社交媒体分享页等。这些页面一旦被投毒，影响范围广。

判断哪些非缓存键会影响页面内容
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 通过修改或添加HTTP头部来判断哪些头部会引起页面内容的变化。
+ 方法
    - 手动修改或添加HTTP头部，指定随机字符来判断头部是否影响页面内容
    - 使用Brupsuite插件Param Miner来自动判断，在burpsuite的URL右键选择Guess headers

示例
--------------------------------------

X-forwarded-Host
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
如果网站以不安全的方式处理非缓存键的输入并允许后续的HTTP响应被缓存，则他们很容易遭受Web缓存中毒。

::

    GET /en?region=uk HTTP/1.1
    Host: innocent-website.com
    X-Forwarded-Host: innocent-website.co.uk

    HTTP/1.1 200 OK
    Cache-Control: public
    <meta property="og:image" content="https://innocent-website.co.uk/cms/social.png" />

x-forwarded-host头的值用于动态生成image的URL，以上的案例可以这样利用：

::

    GET /en?region=uk HTTP/1.1
    Host: innocent-website.com
    X-Forwarded-Host: a."><script>alert(1)</script>"

    HTTP/1.1 200 OK
    Cache-Control: public
    <meta property="og:image" content="https://a."><script>alert(1)</script>"/cms/social.png" />

如果缓存了此响应，则将向/en?region=uk访问的所有用户都会收到XSS影响。

cookie
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Cookie有时也用于在响应中动态生成内容，如果cookie也存在非缓存键则也会收到影响。

X-Forwarded-scheme/X-forwarded-Proto
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
X-Forwarded-scheme/X-Forwarded-Proto头：当值不为https时，表示当前请求以http的方式发送，一般情况下都会返回302跳转到当前URL的https协议请求。当非缓存键是X-Forwarded-scheme头时，如果网站同时支持X-Forwarded-Host则可以通过两者结合达到web投毒的攻击效果。

::

    GET /random HTTP/1.1
    Host: innocent-site.com
    X-Forwarded-Proto: http

    HTTP/1.1 301 moved permanently
    Location: https://innocent-site.com/random

返回缓存信息头
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
暴露太多的响应信息也可能会让攻击更容易。

::

    HTTP/1.1 200 OK
    Via: 1.1 varnish-v4
    Age: 174
    Cache-Control: public, max-age=1800

这里暴露出了缓存的机制和时间，攻击者可以根据此时间来操作。不用大量的重放攻击。
e. Vary头一般情况下值为User-Agent，表示UA也作为缓存键，根据这个，我们可以通过Web缓存攻击特定的UA用户。
f. 有时Web会使用Json传参，并通过JavaScript操作数据，这种情况下就有可能导致基于DOM的XSS问题。
我们需要操作的是让我们攻击服务器上的恶意Json文件投毒到缓存，注意⚠️：如果使用Web缓存中毒使网站从服务器加载恶意Json数据，则需要使用CORS授予网站访问JSON的权限，像下面一样。

::

    HTTP/1.1 200 OK
    Content-Type: application/json
    Access-Control-Allow-Origin: *

    {
        "malicious json" : "malicious json"
    }



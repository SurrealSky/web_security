SSO
========================================

简介
----------------------------------------
单点登录(SingleSignOn，SSO)指一个用户可以通过单一的ID和凭证（密码）访问多个相关但彼此独立的系统。

一般流程
----------------------------------------

首次登录（建立全局会话）
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 第1步：访问受保护资源
    - 用户在浏览器访问业务系统A（SP-A），SP-A检测到请求未携带本地Session，判定用户未登录。
+ 第2步：重定向至认证中心（IdP）
    - SP-A生成一个携带自身身份标识（service或redirect_uri）的重定向请求，将浏览器导向统一的IdP登录页。
    - https://idp.com/login?service=http://app-a.com
+ 第3步：认证中心校验全局登录态
    - IdP先检查浏览器是否有自己的全局Cookie（即TGT或IdP-Session）。
        + 如果没有（首次登录），IdP返回登录页面，要求用户输入账号密码、MFA（多因素认证）等。
        + 用户提交凭证，IdP校验通过。
+ 第4步：建立全局会话并颁发“一次性临时凭证”
    - 写全局Cookie：在IdP的域名下写入Cookie，标志着该浏览器已全局登录（从此无需再输密码）。
    - 生成一次性临时凭证（如CAS的ST，或OAuth2的Authorization Code）：这个凭证是临时的、一次性的，且必须与第2步中的SP身份（service地址）绑定。
    - IdP将浏览器重定向回业务系统A，并在URL中附带这个临时凭证： ``http://app-a.com/?ticket=ST-123456 或 ?code=AUTH_CODE``
+ 第5步：业务应用后台“偷偷”去换用户信息（最关键的安全步骤）
    - 浏览器拿到凭证去访问SP-A，但SP-A绝不信任浏览器直接带来的这个凭证（因为可能被篡改或劫持）。
    - SP-A的后端服务器会拿着这个临时凭证，加上自己的Client秘钥（如果是OAuth2），直接发起后端服务（Server-to-Server）请求IdP的验证接口（如 /serviceValidate 或 /token），进行校验。
    - IdP此时会做严格校验：
        + 凭证是否过期？
        + 凭证是否已被使用过？（一次性）
        + 凭证绑定的 service 地址，是否与SP-A请求时传过来的地址一致？（防止你案例中的劫持）
+ 第6步：返回用户信息，建立本地会话
    - IdP验证通过，将用户信息（用户名、角色等）返回给SP-A的后端。SP-A确认身份后，为当前浏览器生成自己的本地Session（写自己的Cookie）。
+ 至此，用户成功访问应用A。

第二阶段：访问第二个应用（SSO免密效果）
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 重定向：应用B检测未登录，将浏览器重定向到IdP（https://idp.com/login?service=http://app-b.com）。
+ 全局会话命中：浏览器请求IdP时，自动携带了第一阶段种下的全局Cookie。IdP识别出该用户已登录。
+ 自动颁发新凭证：IdP不再询问密码，直接生成一个针对应用B的新的临时凭证，重定向回应用B。
+ 后台换信：应用B的后台拿着新凭证去IdP后台校验（校验绑定关系、时效）。
+ 登录成功：应用B建立自己的本地Session。

示例(CAS协议)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~




安全基石
----------------------------------------
+ 双层会话隔离：IdP管全局（Cookie），SP管本地（Session）。即使你拿到SP的票据，没有IdP的全局Cookie，也无法触发自动发券流程。
+ 后台换信机制：关键的“凭证换用户信息”动作发生在后端服务器之间，浏览器全程看不到用户信息原文，且验证时强制比对绑定地址（service）。
+ 一次性与时效性：所有临时凭证（ST/Code）都是用完即废，防止重放攻击（Replay Attack）。

实现方式
----------------------------------------

票据代理模式
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 特点：认证中心（CAS Server）不直接告诉业务应用“用户是谁”，而是给浏览器一张“一次性兑换券（ST）”。业务应用的后台拿着券去认证中心后台兑换用户信息。
+ 代表
    - CAS协议
        + 基本概念
            - TGT: 存在CAS Server服务端,代表用户的全局 SSO 会话，是服务端的“会话本体”，但由于历史原因，可能会以cookie形式存在于主域。
            - TGC：浏览器CAS域自动携带，发往 CAS Server，是 TGT 的“钥匙/索引”，用来向 CAS Server 证明“这个浏览器已经登录过”。
            - ST（service ticket）：作为 URL 参数在浏览器与 SP 之间传递，一次性的服务票据，专门用来向某一个 SP 证明“这个用户已经被 CAS 认证过”。
            - TGC 和 TGT 的关系，类似于 Cookie 和 Session 的关系：TGC 是浏览器里的那个 Cookie 值，TGT 是服务端对应的会话对象。
        + 第一次登录（还没有 TGC）
            - 浏览器访问受保护的 SP-A，SP-A 发现自己没有该用户的局部会话，把浏览器重定向到 CAS Server 的登录地址。
            - CAS Server 发现请求里没有 TGC，返回登录页面，要求用户输入凭据。
            - 凭据验证通过后，CAS Server 在服务端创建 TGT，同时向浏览器下发 TGC Cookie（通常名为 CASTGC，Domain 在 CAS Server 域），并生成一个 ST。
            - 浏览器被重定向回 SP-A，URL 上带着 ?ticket=ST-...。
            - SP-A 的后端拿着这个 ST 去 CAS Server 验证。验证成功后，CAS Server 立即销毁这个 ST（一次性），SP-A 在自己的服务端建立局部会话，并给浏览器下发SP-A 自己的业务 Cookie。
        + 访问另一个 SP（SSO 生效）
            - 浏览器访问 SP-B，SP-B 同样没有局部会话，重定向到 CAS Server。
            - 浏览器访问 CAS Server 时，自动带上了 TGC。
            - CAS Server 用 TGC 查到对应的 TGT，确认全局 SSO 会话仍然有效，不再要求用户输入密码，直接生成一个新的 ST 给 SP-B。
            - SP-B 拿 ST 去 CAS Server 验证，成功后建立自己的局部会话。
        + 示例
            - SP-A SSO登录，重定向到CAS，CAS要求用户登录

            ::

                POST /login?service=https://b.AAA.com HTTP/2
                Host: sso.AAA.com
                Cookie: SESSION=a1eef5fe-98df-42dc-a3dc-01f6179f4423;
                User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0
                Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
                Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5
                Accept-Encoding: gzip, deflate, br
                Content-Type: application/x-www-form-urlencoded
                Content-Length: NUMBER
                Origin: https://sso.AAA.com
                Referer: https://sso.AAA.com/login?service=https://b.AAA.com/cas
                Upgrade-Insecure-Requests: 1
                Sec-Fetch-Dest: document
                Sec-Fetch-Mode: navigate
                Sec-Fetch-Site: same-origin
                Sec-Fetch-User: ?1
                Priority: u=0, i
                Te: trailers

                tenantCode=AAA&username=xxxx&password=xxxxxxx&lt=

                HTTP/2 302 Found
                Date: Thu, 08 Oct 2026 12:04:27 GMT
                Content-Length: 0
                Location: https://b.AAA.com/cas?ticket=ST-477487-3DyrBjRlJ5x1nIaxZTj7-www.AAA.com
                Access-Control-Allow-Origin: https://sso.AAA.com
                Access-Control-Allow-Methods: POST, GET, OPTIONS, DELETE,PUT
                Access-Control-Max-Age: 3600
                Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept
                Access-Control-Allow-Credentials: true
                Cache-Control: no-store
                Set-Cookie: CASPRIVACY=""; Expires=Thu, 01-Jan-1970 00:00:10 GMT; Path=/; Secure
                Set-Cookie: tgt_cn=TGT-134834-oKeAtakShPiZXTdv1Y7A2XjVlUwd2FMZqXIT57GgZDxQeeZAvd-www.AAA.com; Path=/; Domain=AAA.com;
                Set-Cookie: TGC=VEdULTEzNDgzNC1vS2VBdGFrU2hQaVpYVGR2MVk3QTJYalZsVXdkMkZNWnFYSVQ1N0dnWkR4UWVlWkF2ZC13d3cuQUFBLmNvbUAxLjEuMS4xQE1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQ7IHJ2OjE1Ny4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzE1Ny4w; Path=/; SameSite=None; Secure

                注意：TGC是编码后的TGT，TGT是IdP的全局会话凭证，类似于Cookie。浏览器拿到TGC后，会在后续访问IdP时自动携带，触发免密登录。

            + CAS根据service参数，重定向浏览器回SP-A，并附带一次性临时凭证ST

            ::

                GET /login?service=https://b.AAA.com/cas HTTP/2
                Host: sso.AAA.com
                Cookie: TGC=VEdULTEzNDgzNC1vS2VBdGFrU2hQaVpYVGR2MVk3QTJYalZsVXdkMkZNWnFYSVQ1N0dnWkR4UWVlWkF2ZC13d3cuQUFBLmNvbUAxLjEuMS4xQE1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQ7IHJ2OjE1Ny4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzE1Ny4w
                User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0
                Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
                Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5
                Accept-Encoding: gzip, deflate, br
                Referer: https://b.AAA.com/site/home
                Upgrade-Insecure-Requests: 1
                Sec-Fetch-Dest: document
                Sec-Fetch-Mode: navigate
                Sec-Fetch-Site: same-site
                Sec-Fetch-User: ?1
                Priority: u=0, i
                Te: trailers

                HTTP/2 302 Found
                Date: Thu, 08 Oct 2026 12:11:37 GMT
                Content-Length: 0
                Location: https://b.AAA.com/cas?ticket=ST-477594-LvUvZe6RS5dJ0emg5woR-www.AAA.com
                Cache-Control: no-store
                Set-Cookie: SESSION=ff40acd6-df6d-4f70-ae1f-cb7553eefd3b; Path=/; HttpOnly

            + SP-A拿到ST后，后台去CAS验证ST，并换取用户信息(这里换取SESSION)

            ::

                GET /cas?ticket=ST-477594-LvUvZe6RS5dJ0emg5woR-www.AAA.com HTTP/2
                Host: b.AAA.com
                User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0
                Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
                Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5
                Accept-Encoding: gzip, deflate, br
                Referer: https://sso.AAA.com/
                Upgrade-Insecure-Requests: 1
                Sec-Fetch-Dest: document
                Sec-Fetch-Mode: navigate
                Sec-Fetch-Site: same-site
                Sec-Fetch-User: ?1
                Priority: u=0, i
                Te: trailers

                HTTP/2 302 Found
                Date: Thu, 08 Oct 2026 12:11:47 GMT
                Content-Length: 0
                Location: https://b.AAA.com
                Set-Cookie: rememberMe=deleteMe; Path=/; Max-Age=0; Expires=Wed, 07-Oct-2026 12:11:47 GMT; SameSite=lax
                X-Content-Type-Options: nosniff
                X-Xss-Protection: 1; mode=block
                Cache-Control: no-cache, no-store, max-age=0, must-revalidate
                Pragma: no-cache
                Expires: 0
                X-Frame-Options: DENY
                Set-Cookie: SESSION=YzA0NmU5OTMtNzQwMC00YmNhLWE3N2QtN2IyODBlZjZmMDM3; Path=/; Secure; HttpOnly; SameSite=Lax

                https://b.AAA.com网站的授权就是SESSION=YzA0NmU5OTMtNzQwMC00YmNhLWE3N2QtN2IyODBlZjZmMDM3
                
    - SAML 2.0（常用于企业级跨域联邦认证）
+ 优势：安全性极高，用户密码永远不经过业务系统，且票据强绑定来源。

直接令牌模式
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 特点：认证通过后，认证中心直接给浏览器返回一个Access Token（访问令牌）。业务应用拿着这个令牌去资源服务器获取数据，或者令牌本身通过JWT（JSON Web Token）格式自包含用户信息（经过数字签名，不可篡改）。
+ 代表：OIDC（OpenID Connect）（基于OAuth 2.0）、JWT（自包含式令牌）。
+ 优势：无状态、易于水平扩展，适合前后端分离和微服务架构。

其他常见实现方式
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ Kerberos：内网（尤其是Windows域环境）常用的对称密钥认证方式，依赖KDC（密钥分发中心）。
+ 反向代理/网关统一认证：在Nginx或Spring Cloud Gateway层配置Auth过滤器，统一拦截请求并转发给认证中心（这种方式不依赖ST票据，依赖网关和Session共享）。

攻击面
----------------------------------------

协议参数污染与逻辑绕过
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 基本原理：漏洞发生在"浏览器向IdP（认证中心）发起请求"的阶段，攻击者通过篡改参数来劫持认证结果。
+ Open Redirect（开放重定向）
    - service 或 redirect_uri 参数校验不严，导致登录成功后跳转到钓鱼网站。虽然这本身不算SSO劫持，但它常作为高阶攻击的跳板（如结合以下第2点）。
+ OAuth中的“回调劫持”（Callback Hijacking）
    - 在OAuth 2.0/OIDC中，如果 redirect_uri 校验不严（允许前缀匹配或路径遍历），攻击者可以将回调地址指向自己的站点（https://攻击者.com/callback）。当用户授权后，授权码（Code）会被直接发送到攻击者的服务器日志里，攻击者拿Code就能换Token登录。
+ SAML中的签名绕过（XML Signature Wrapping）
    - 在SAML协议中，攻击者通过篡改断言（Assertion）中的用户名字段，并利用XML解析漏洞绕过数字签名校验，从而以管理员身份登录目标应用。

票据/凭证的劫持与重放
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 基本原理: 漏洞发生在“浏览器拿到票据往回跳转”的阶段。
+ Authorization Code（授权码）截取：如果浏览器存在恶意插件，或者HTTP请求被中间人（MITM）监听，攻击者可以直接截取URL上的 ?code=xxx 或 ?ticket=ST-xxx。
    - 利用前提：正如你实践失败的教训，单纯的Code/ST劫持在现代SSO中极难直接利用，因为Code与回调地址绑定且一次性。但如果开发者为了调试，将 redirect_uri 设置为 \*（通配符），或者没有校验Code与state的绑定关系，攻击者就能用截获的Code在自己浏览器换Token。
+ TGT（全局Cookie）的窃取（致命一击）：通过XSS（跨站脚本攻击）或物理接触，偷取IdP域下的全局会话Cookie。这是危害最高的，因为攻击者不需要代码，直接把Cookie导入浏览器，就能像正常用户一样点击任何子系统，IdP会自动发新的ST，无需任何密码。

跨域与Cookie安全机制缺陷
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ Cookie Domain 设置过于宽松
    - 如果IdP的Cookie设置了 Domain=.example.com（允许所有子域名），而某个子域名（如 dev.example.com）被攻击者通过域名接管（Subdomain Takeover）拿下，攻击者就可以在该子域名下篡改或窃取Cookie。
+ 未开启HttpOnly & Secure
    - 如果Cookie未设置 HttpOnly，网站存在XSS漏洞时，攻击者能直接用JavaScript读取TGT并发回自己的服务器；如果未设置 Secure，在HTTP明文传输时可能被中间人嗅探。

CSRF（跨站请求伪造）在SSO中的变种
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 基本原理：登录流程本身为了防止CSRF，引入了 state 参数（OAuth）或 nonce（OIDC）。
+ Login CSRF（登录伪造）
    - 攻击者利用自己的账号登录系统，获取合法的 code，然后诱导受害者点击携带该 code 的链接。如果系统没有将 code 与当前浏览器的会话（state）强绑定，攻击者就可能将受害者的浏览器“绑定”到自己的账号上（即受害者看到的页面其实是攻击者的数据，反之亦然）。
+ Logout CSRF（注销劫持）
    - 攻击者在钓鱼页面中嵌入一个隐藏的 <img src="https://idp.com/logout">。受害者点击后，被迫退出SSO，必须重新输入密码，此时弹出的真实登录框可能被攻击者的钓鱼弹窗覆盖。

会话生命周期管理不当
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 单点注销（SLO）不彻底
    - 用户从IdP注销后，IdP没有主动通知各个子系统（SP）清除本地Session。导致用户以为退出了，但实际上子系统A的本地Cookie依然有效，后续访问者无需SSO校验直接进入。
+ Session Fixation（会话固定）
    - 攻击者预先设定一个已知的Session ID，诱导受害者使用该Session ID登录IdP。如果IdP登录后没有重置Session ID，攻击者拿着这个已知ID就能直接接管会话。
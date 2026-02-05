攻击面分析
========================================

利用渲染进程本身进行RCE
----------------------------------------
+ 通过NodeJs共享库RCE
+ 通过chromium Nday RCE

通过IPC影响主进程进行RCE
----------------------------------------
+ 需要主进程ipcmain，实现了危险方法
    ::
    
        例如主进程：
        ipcMain.on('fetch-data', (event, data) => {
            exec(data);  // Potentially dangerous function call
        });
        渲染进程：
        ipcRenderer.send('fetch-data', 'rm -rf /');
+ 需要当前执行上下文可以访问IPC

常规利用方法
----------------------------------------
+ 分析选项开启状态
    ::
    
        grep -r "sandbox:" ./
        grep -r "nodeIntegration:" ./
        grep -r "contextIsolation:" ./
+ NI为true, CISO为 false，SBX为false
    - 允许了页面之间访问nodejs共享库，只要获取目标应用的一个XSS漏洞，就能直接通过访问NodeJS共享库，升级为XSS漏洞。
    - NI配置方法：在man.js中webPreferences中配置了nodeIntegration为true/false
+ NI为false, CISO为false，SBX为false
    - 关闭了Nodejs集成，导致我们不能在web页面上下文访问Nodejs共享库。
    - 因为上下文隔离没有开启，web页面和preload.js处于同一上下文中，导致我们可以通过污染原型链，获取preload,js的函数，进行ipcmain调用，命令执行等。
    - 限制条件
        ::
        
            Electron<10
            - 可以使用原型链污染获取remote/IPC模块
            - Remote模块可以直接通过主进程执行node js绕过沙箱
            Electron 10<version<14
            - 可以使用原型链污染获取remote/IPC模块
            - 需要Remote Module Explicitly Enabled，才可以使用remote模块RCE
            - 主进程IPC存在错误配置，通过进程间通信IPC，进行RCE
            Electron >14
            - 只能通过原型链污染获取IPC模块
+ NI为true/false, CISO为true，SBX为false
    - 因为没有开启沙箱，通过Chrome渲染进程远程代码执行漏洞，就可以直接RCE。
    - Chromium 83、86、87、88版本，如果electorn内置了Chromium就可以通过XSS，直接攻击，进行RCE。
+ NI:false, CISO:true, SBX为true
    - 有沙箱， 我们只能通过IPC进行攻击，但是如果我们js处于iframe之中，可能没有ipc访问权限,需要绕过。
    - 绕过思路
        + iframe下无ipc接口绕过
        + 关闭CISO,直接使用IPC，绕过限制
        + 关闭CISO,使用原型链污染获取remote模块进行RCE
        
自定义协议
----------------------------------------
+ electron应用可以注册自己的url协议，例如custom://。
+ 这样可以通过浏览器直接打开应用，如果对url协议的处理不当可能导致rce等。
+ 检测方法
    - 代码查找法：查找 **registerHttpProtocol** 方法调用
    - 工具： **UrlProtocolView**

代码审计
----------------------------------------
+ 寻找输入点
    - 如xss漏洞等

更新升级
----------------------------------------
+ MITM
    - HTTP方式升级
+ windows升级提权
    ::
    
        恶意工程：https://github.com/parsiya/evil-electron/
        1.告诉服务下载更新（windows一般通过命名管道）。
        2.将C:\Program Files (x86)\vendor\electron-app\ 中的所有内容复制到 C:\ProgramData\[redacted]\Updates（下载更新的位置）。
        3.删除下载的安装程序，但复制其文件名 (GUID.exe)。
        4.将electro-app.exe重命名为下载的安装程序的名称 (GUID.exe)。
        5.将目标中的 resources\app.asar文件替换为我自己的后门文件。
        6.继续Windows服务运行安装程序。
        7.弹出具有SYSTEM权限的cmd。
+ 免杀技术
    ::
    
        恶意代码藏于app.asar文件中。
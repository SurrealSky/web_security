逆向分析
========================================

asar文件
----------------------------------------
+ 程序解包
    ::
    
        windows系统安装node.js
        在其目录中执行：npm install asar -g
        asar e app.asar app //解压拿到源码
+ 程序打包
    ::
    
        asar p app app.asar //重新打包
+ js格式美化
    ::
    
        npm install uglify-js -g
        uglifyjs main.js -b -o _main.js
+ 注意
    - app.asar一般都没有做进一步的加密处理，所以拿到源码不难
    - 不排除有的厂商可能在这方面做了一定的保护，就需要我们自己去逆向找到解密方法了，可以参考coco2d等。
    - 拿到的js源码一般都会做一定的混淆，通过搜索js混淆技术和反混淆、格式化等，基本可以恢复到能够方便阅览的源码。
    - 如果想验证某些功能，或者做些修改，可以通过重打包然后替换app.asar。

信息收集
----------------------------------------
+ 查看版本
    ::
    
        Devtool查看法：
        前提是App启用了node Integration属性。
        Devtool控制台输入：process.versions.electron
        
        UA查看法：
        使用Devtool查看网络通信数据，查看User Agent头。
        
        修改代码法：
        var fs = require("fs");
        var querystring= require('querystring');

        console.log("准备写入文件");
        fs.writeFile('input.txt', querystring.stringify(process.versions),  function(err) {
           if (err) {
               return console.error(err);
           }
           console.log("数据写入成功！");
           console.log("--------我是分割线-------------")
           console.log("读取写入的数据！");
           fs.readFile('input.txt', function (err, data) {
              if (err) {
                 return console.error(err);
              }
              console.log("异步读取文件数据: " + data.toString());
           });
        });
        保存以上js内容为getVersionInfo.js，保存于解包后的文件夹中
        修改package.json的main字段为getVersionInfo.js
        重新封包，替换原来的.asar文件。
+ 功能特性
    - 查看特性: ``npx @electron/fuses read --app *.exe``
    - **runAsNode** ：是否考虑ELECTRON_RUN_AS_NODE环境变量。
    - **cookieEncryption** :磁盘上的cookie存储是否使用操作系统级别的加密密钥进行加密。
    - **nodeOptions** ：是否遵守--inspect、--inspect-brk 等标志。
    - **embeddedAsarIntegrityValidation** ：macOS上的一项实验性功能，该功能在加载app.asar文件时验证其内容。
    - **onlyLoadAppFromAsar** ： 改变了Electron用来定位应用程序代码的搜索系统。默认情况下，Electron将按照以下顺序搜索 app.asar -> app -> default_app.asar。
    - **loadBrowserProcessSpecificV8Snapshot** ：更改浏览器进程使用的V8快照文件。
    - **grantFileProtocolExtraPrivileges** ：从 file:// 协议加载的页面是否被赋予超出它们在传统Web浏览器中所获得的权限的权限。
    - 总结
        + **绕过验证** ：开启 EnableEmbeddedAsarIntegrityValidation 让程序在启动时检查 .asar 文件的完整性。程序执行时会读取.asar文件的头部，计算hash后和二进制程序内部的值进行对比，如果对比通过了就加载.asar文件进行执行。问题在于，程序只会校验头部计算后的hash，但不会校验头部中的记录的hash是否有效，因此如果修改了文件内容，文件大小不变，偏移也就不会变（偏移在头部），就能够绕过验证。
        + **asar劫持** ：onlyLoadAppFromAsar关闭后，劫持优先级高的文件。
+ Sandbox（沙箱）
    - 即Chromium的沙盒特性，如果开启了这个选项， 渲染进程将运行在沙箱中，限制了大多数系统资源的访问，包括文件读写，新进程启动等， preload.js和网页中的js都会受到这个选项的影响
    - 该选项会随着Node Integration的开启而关闭
    - Sandbox选项从Electron 20开始默认为开启状态
    - 检查方法
        ::
        
            1.查找 app.enableSandbox()函数调用
            2.查找sandbox: 选项设置，一般如下代码：
            const win = new BrowserWindow({
                webPreferences: {
                  sandbox: false
                }
              })
+ Node Integration（Node集成）
    - Node集成，是否开启网页Js Nodej共享库的访问，如果开启的话，网页js将拥有直接Nodejs的执行权限，包括进程启动，文件加载等
    - preload.js Node集成是一直开启的，不受这个选项影响
    - 即使这个选项开启，上下文隔离选项开启的话，网页Js仍然无法访问Nodejs共享库
    - 检查方法
        ::
        
            查找nodeIntegration: 选项设置，一般如下代码：
            const win = new BrowserWindow({
                webPreferences: {
                  nodeIntegration: true
                }
              })
+ Context Isolation（上下文隔离）
    - Electron的特性，使用了与Chromium相同的Content Scripts技术来实现。确保preload脚本和网页js在一个独立的上下文环境中
    - 开启后渲染页面的js中无法引入Electron和Node中的各种模块
    - 如果想在其中使用这部分功能，需要配置preload.js，使用contextBridge来暴露全局接口到渲染页面的脚本中
    - Electron 12开始默认启用
    - 检查方法
        ::
        
            查找contextIsolation: 选项设置
+ js敏感信息扫描
    - jsluice：``go install github.com/BishopFox/jsluice/cmd/jsluice@latest``
    - 查找urls
        ::
        
            linux:
            find . -type f -name "*.js" | jsluice urls | jq -r '.url' | sort -u
            windows:
            for /r C:/Users/Administrator/Desktop/app %i in (*.js) do @echo %i|jsluice urls
    - 查找敏感信息
        ::
        
            for /r C:/Users/Administrator/Desktop/app %i in (*.js) do @echo %i|jsluice secrets

内存分析
----------------------------------------

内存对象分类
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ JavaScript对象 (V8 Heap)
    - 核心部分，存在于主进程和渲染进程，其JavaScript代码执行环境都由V8 JavaScript引擎管理。
    - 所有​​你用 JavaScript 代码创建的对象（变量、函数、数组、自定义对象实例、DOM 元素引用等）都存在于 V8 引擎管理的堆内存中。
    - 这是 JavaScript 开发者最直接接触到的内存。
+ DOM 对象(Blink/WebKit)
    - 在渲染进程中，当你操作 document、window、div等时，你是在操作 DOM。
    - DOM 本身是一个用 C++ 实现的复杂对象树（由 Blink 渲染引擎管理）。
    - JavaScript 代码通过 V8 提供的 ​​Wrapper 对象​​ 来访问和操作这些底层的 C++ DOM 对象。
    - Wrapper是一个特殊的JS对象，它持有对底层 C++ DOM 对象的引用，并将 JS 操作转发给 C++ 实现。
    - 存在 JS Wrapper 对象与底层 C++ 实现对象的关联。
+ Node.js内置模块对象
    - 在主进程和启用了Node.js集成的渲染进程中，使用的Node.js的 API（如 fs, net, path, process等）。
    - 核心功能通常是用 C++ 实现的（例如 fs.readFile最终调用 libuv 和操作系统 API）。
    - 当你调用 require('fs')时，你得到一个 JavaScript 对象。这个 JS 对象的方法内部会通过 Node.js/V8 的绑定机制调用底层的 C++ 代码。
    - 存在 JS Wrapper 对象与底层 C++ 实现对象的关联。
+ Electron特有API对象
    - Electron 提供的 API，如 BrowserWindow, ipcRenderer, ipcMain, app, dialog等
    - 核心逻辑也是用 C++ 实现的（或者 TypeScript 调用 C++）。
    - 当JS 代码中调用 new BrowserWindow()时
        ::
        
            V8 创建一个 JS 对象（BrowserWindow实例）。
            Electron 的 C++ 部分会创建一个对应的底层 C++ BrowserWindow对象（管理原生窗口创建、消息循环等）。
            这个 JS 对象充当了底层 C++ 对象的 Wrapper/Proxy。​​ 
            JS 对象上的方法调用（如 win.loadURL()）会被转发到底层的 C++ 对象执行实际的操作。
+ 原生资源/缓冲区​​
    - 例如 Buffer对象（Node.js）、ArrayBuffer、SharedArrayBuffer、ImageBitmap等
    - 这些对象通常在 V8 堆外分配内存（可能由 V8 管理，也可能由操作系统或原生模块直接管理），但通过 JS API 暴露给 JavaScript 访问。
    - 它们代表了原始的内存块（图片数据、文件内容、网络数据等）。
+ V8和引擎内部对象
    - V8 引擎本身需要内存来管理其内部状态（编译后的代码、优化信息、垃圾回收元数据等）。
    - Blink/WebKit 渲染引擎也有其庞大的 C++ 内部数据结构（渲染树、样式计算、网络栈、GPU 通信等）。

对象绑定
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 不是每个 JavaScript 对象都对应一个封装的 C++ 对象。​​
+ 纯 JavaScript 对象
    - 绝大多数你创建的普通 JavaScript 对象（例如 let obj = { name: 'Alice', age: 30 };或 function greet() { ... }）​​只存在于 V8 堆中​​。
    - 它们没有直接的、一对一的底层 C++ 对象封装。
+ Wrapper/Proxy 对象
    - 当你与​​浏览器环境​​（DOM）或​​Node.js/Electron 环境​​（fs, BrowserWindow, process）交互时，你操作的 JavaScript 对象（如 document.getElementById('myDiv')返回的对象，或 new BrowserWindow()返回的对象）​​通常是 Wrapper 对象​​。
    - 这些 Wrapper JS 对象​​持有对底层 C++ 实现对象的引用​​。
    - 调用这些 JS 对象的方法或访问其属性，最终会通过 V8 的绑定机制调用到 C++ 代码。
    - 这些 C++ 对象负责执行实际的、需要原生能力的操作（操作文件、创建窗口、网络请求、渲染像素等）。
    - 关键点：​​ 一个 JS Wrapper 对象对应一个（或一组相关的）底层 C++ 对象。这是 Electron/Node.js/浏览器将原生能力暴露给 JavaScript 的核心机制。
+ 简单值类型
    - number, string, boolean, null, undefined, symbol这些基本类型值通常直接由 V8 处理，不需要单独的 C++ 对象封装（虽然它们在 V8 内部也有表示）
+ 原生资源缓冲区
    - Buffer/ArrayBuffer等对象本身是 JS 对象，但它们管理的内存块通常在 V8 堆外。
    - 它们可以被视为一种特殊类型的 Wrapper，包装了一块原始内存。

程序调试
----------------------------------------
+ 添加代码法
    ::
    
        asar extract app.asar app //解压拿到源码
        根据package.json文件main节点，查看入口代码文件：
        插入mainWindow.webContents.openDevTools();
        mainWindow.webContents.openDevTools({mode:'right'})；
        mainWindow.webContents.openDevTools({mode:'bottom'})；
        mainWindow.webContents.openDevTools({mode:'left'})；
        mainWindow.webContents.openDevTools({mode:'detach'})
        mainWindow.webContents.openDevTools({mode:'undocked'})
        注：如果代码进行了混淆，无法找到BowserWindow创建位置，就在文件头部或者末尾添加：
        let {BrowserWindow} = require('electron');
        let timer = null;
        timer = setInterval(()=>{
            let windows = BrowserWindow.getAllWindows();
            if(windows.length > 0){
                windows.forEach(v=>{
                    if(v){
                        v.webContents.openDevTools();
                    }
                })
                clearInterval(timer);
            }
        },5000);
        //重新打包，替换原始app.asar
        asar pack app app.asar 
        注：这里调试的是渲染进程。
        假如打开程序5s后，程序关闭，那么可能是对devtool窗口有监控，则可以关闭devtool打开的事件监听：
                let {BrowserWindow} = require('electron');
        let timer = null;
        timer = setInterval(()=>{
            let windows = BrowserWindow.getAllWindows();
            if(windows.length > 0){
                windows.forEach(v=>{
                    if(v){
                        v.webContents.removeAllListeners('devtools-opened');
                        v.webContents.openDevTools();
                    }
                })
                clearInterval(timer);
            }
        },5000);
        或者添加以下代码将窗口的close置空：
        v.close = () =>{};
+ 端口调试法
    ::
    
        调试渲染进程：
        命令行启动目标程序 *.exe -remote-debugging-port=9222
        浏览器中即可出现对应的页面，点击inspect调试
        
        调试主进程：
        下载对应版本的node和electron，然后将node添加到环境变量中。
        配置electron下载源，全局安装npm install -g electron@17.1.2 --arch=ia32
        npm config set ELECTRON_MIRROR https://npm.taobao.org/mirrors/electron/
        使用Electron提供的 ​--inspect​ 和 ​--inspect-brk​ 开关以调试模式打开程序。
        --inspect-brk=[port] 和--inspector 一样，但是会在JavaScript 系统脚本的main.js第一行暂停运行。
        1.第一种方法是在调试的js脚本文件前面插入console.log('debug');重新调试。
        输出日志之后，会在命令窗口出现调试的文件
        点击文件之后，再下断点，重新调试即可。
        2.第二种方式是在调试的js脚本文件前面插入debugger;即可。
        使用以下命令：
        electron --inspect[=5858] your/app
        注：默认是9229端口。
        
        安装chrome浏览器，打开chrome://inspect
        配置Discover network targets，添加9222，9229端口或自定义的端口
        加载源码，在js入口处添加断点。
+ 初始调试法
    ::
    
        找到index.html，在body部分添加：
        <script>alert("hello")</script>
        重新封包，打开程序，在出现弹框时，按下enter的同时，按ctrl + shift + i就可以打开控制台。
+ Debugtron工具
    ::
    
        地址：https://github.com/pd4d10/debugtron
        注：可调试主进程和渲染进程。
+ 设置代理
    ::
    
        /app.exe --args --proxy-server=127.0.0.1:8080 --ignore-certificate-errors
+ 抓包工具
	- httptoolkit: ``https://httptoolkit.com/download/win-exe/``
+ 无法打开devtools
	- 原因分析
		+ 程序监听了控制台的打开事件，当发现控制台打开，则立刻将其关闭。
		+ 程序在用BrowserWindow创建窗口时，配置了webPreferences中的devTools为false。
		+ 程序在打包时，去除了Electron的控制台功能模块。
	- 绕过
		+ 第一种：通常是使用的是devtools-opened事件），可以通过解绑事件或移除相关代码的方式绕过。
		+ 第二种：程序入口文件寻找窗口的devTools配置项，并修改它。
		+ 第三种
			::
			
				(1)解压app.asar后，在app文件夹中新建一个js文件并写入以下代码：
				const { app, BrowserWindow } = require("electron");

				//创建窗口
				function createWindow () {
				let mainWindow = new BrowserWindow({
				title: "测试",
				width: 670,
				height: 420,
				offscreen: true,
				show: true,
				titleBarStyle: "customButtonsOnHover",
				backgroundColor: "#fff",
				acceptFirstMouse: true, //是否允许单击页面来激活窗口
				allowRunningInsecureContent: true,//允许一个 https 页面运行 http url 里的资源
				webPreferences: {
				devTools: true, //是否允许打开调试模式
				webSecurity: false,//禁用安全策略
				allowDisplayingInsecureContent: true,//允许一个使用 https的界面来展示由 http URLs 传过来的资源
				allowRunningInsecureContent: true, //允许一个 https 页面运行 http url 里的资源
				nodeIntegration: true//5.x以上版本，默认无法在渲染进程引入node模块，需要这里设置为true
				}
				});
				mainWindow.loadURL('about:blank');
				// 完成第一次绘制后显示
				mainWindow.on('ready-to-show', () => {
				mainWindow.webContents.openDevTools();
				})
				// 窗口关闭
				mainWindow.on('closed', function () {
				mainWindow = null
				});
				}
				// 主进程准备好以后创建窗口
				app.on('ready', () => {
				createWindow();
				});
				(2)打开app文件夹中的package.json文件，将入口（main）指向新建的js文件。
				(3)启动程序，看打开的窗口是否有控制台，若有，则说明程序内打包了控制台模块，若无，则说明没有打包。

注入hook
----------------------------------------
+ did-finish-load事件
    ::
    
        首先在窗口创建部分添加事件：
        mainWindow.webContents.on("did-finish-load", function() {
        const js = fs.readFileSync(path.join(__dirname, 'netflixHook.js')).toString();
        mainWindow.webContents.executeJavaScript(js);
        });
        netflixHook.js文件如下：
        const injection = () => {
            //这里填写js hook代码
        };
        inject();

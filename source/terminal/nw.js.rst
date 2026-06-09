nw.js程序
========================================

基础
----------------------------------------
+ NW.js的本质是将Chromium浏览器引擎和Node.js运行时融合在同一个进程中，共用同一个V8 JavaScript引擎实例。
+ 这意味着在同一个页面中，你可以直接调用Node.js的API来读写文件、执行系统命令，这一点从SRC漏洞挖掘的角度来看至关重要。

两种模式
----------------------------------------
+ 独立环境模式 (Separate Context Mode) / 普通框架 (Normal Frame)
	- 这是默认的安全模式。在这种模式下，Web页面 (Browser Context) 中默认无法直接调用Node.js的require。页面脚本需要通过<script>标签等方式加载，运行在受限的“浏览器环境”中。
+ 混合环境模式 (Mixed Context Mode) / Node框架 (Node Frame)
	- 当页面符合特定条件时，会获得“超级权限”。运行在此模式下的页面（Node Frame）可以访问Node.js/NW.js API，并能绕过同源策略等所有Web安全沙箱限制。
+ 节点框架 的判定，一个页面要成为Node Frame，必须同时满足以下四个条件：
	- 配置文件 (package.json) 中的 nodejs 设置为 true。
	- 配置为 ``"node-remote": "*"`` 或 ``"node-remote": "http://*"`` 等宽松策略。
	- 框架和其父框架没有 nwdisable 属性。
	- 框架和父框架不在 <webview> 标签内。

编译方式
-------------------------
+ NW.js的编译方式与Electron类似，都是基于Chromium和Node.js的源代码进行构建。开发者可以选择使用官方提供的预编译版本，或者根据需要自行编译。
	- 官方预编译版本：NW.js官方会定期发布预编译的二进制文件，支持Windows、macOS和Linux等多个平台。开发者可以直接下载并使用这些版本，无需进行复杂的编译过程。
	- 自行编译：对于需要定制功能或优化性能的开发者，可以选择从源代码自行编译NW.js。这通常涉及到获取Chromium和Node.js的源代码，配置编译环境，并按照官方文档中的步骤进行构建。自行编译可以让开发者更好地控制NW.js的功能和性能，但也需要更多的技术知识和时间投入。
+ 打包方式
	- 松散文件模式（Folder Mode）：直接将package.json、index.html及node_modules放在nw.exe同级目录或package.nw文件夹中。这是最容易分析的，直接查看文件即可。
	- ZIP合并模式（ZIP Mode）：将源码打包成package.nw（本质是ZIP），放在nw.exe同级目录，或通过命令copy /b nw.exe+package.nw app.exe合并为一个独立的EXE文件。这种方式需要先解压package.nw才能分析源码。
	- JS编译加密（V8 Snapshot）：开发者可能使用NW.js自带的nwjc工具将JS源代码编译为二进制字节码（.bin文件）。这种方式无法直接看到源码，需要使用对应的nwjsc工具或IDA Pro进行逆向分析。

程序特征
--------------------------
+ NW.js程序的特征主要体现在其文件结构和配置文件上。一个典型的NW.js应用程序通常包含以下几个关键文件和目录：
	- package.json：这是NW.js应用程序的核心配置文件，定义了应用的基本信息、入口文件、权限设置等。
	- index.html：这是应用程序的主页面，通常作为应用的入口点。
	- node_modules/：如果应用使用了Node.js模块，这个目录会包含所有安装的模块。
	- assets/：这个目录通常用于存放应用程序的静态资源，如图片、样式表等。

调试方式
--------------------------
+ NW.js提供了多种调试方式，开发者可以根据需要选择适合的调试工具和方法：
	- DevTools：NW.js内置了Chromium的开发者工具，开发者可以通过右键点击页面元素选择“检查”来打开DevTools进行调试。这对于调试前端代码非常方便。
	- Node Inspector：对于需要调试Node.js部分的代码，开发者可以使用Node Inspector工具。通过在命令行中启动NW.js时添加--inspect参数，可以启用Node.js的调试功能，然后使用Chrome DevTools连接到指定的调试端口进行调试。
	- 日志输出：开发者还可以通过在代码中添加console.log语句来输出日志信息，这对于快速查看变量值和程序流程非常有帮助。
+ 打开DevTools
	- 修改根目录下的 package.json，把 chromium-args里的 --disable-devtools删掉，或者改成 --auto-open-devtools-for-tabs。
	- 在package.json中设置"chromium-args": "--remote-debugging-port=9222"，然后使用Chrome浏览器访问http://localhost:9222来连接调试。
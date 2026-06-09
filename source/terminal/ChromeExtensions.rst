chrome/edge浏览器插件
========================================

基础
----------------------------------------
Chrome 插件（扩展程序，Extension）是运行在浏览器中的小程序，可以增强浏览器功能或与当前浏览的页面交互。插件通常由 HTML、CSS、JavaScript 以及一个清单文件（manifest.json）组成，每个插件都有唯一的扩展 ID，并可申请特定权限来访问 Chrome API 或用户数据。

核心组件
------------------------
+ manifest.json：清单文件（插件入口），声明元数据、权限、组件映射关系
+ Background(Service Worker）： **权限最高** ， **独立进程** ，后台服务脚本，事件驱动、非持久化、空闲后回收
+ ContentScript：注入页面的脚本，可直接操作 DOM，但与页面 JS 环境隔离
+ Popup/SidePanel​：弹出页面，独立窗口，点击工具栏图标弹出的临时交互窗口,拥有完整的 Chrome API权限
+ Sandbox Page​: 网页进程​，权限最低 (隔离执行)，完全无法访问 chrome.*系列 API，唯一优势是内容安全策略（CSP）较松散，允许使用 eval() 和 new Function() 等动态代码执行方法。它通常是隐藏的 <iframe>，被嵌入在当前打开插件的页面（即当前浏览的网页）中的，没有 UI，用户无感知，只负责在后台默默处理数据。这一过程通常由 Content Script​ 在页面加载时自动完成
+ Options Page：选项页面，持久化配置界面

进程隔离
------------------
+ Background Service Worker：运行在扩展独立进程。它没有 window对象，无法直接接收 postMessage。它是大脑的“后台服务”。
+ Renderer Process：网页、Content Script、Sandbox 都运行在这里。它们共享内存空间（但 JS 上下文隔离）。
+ 通信桥梁: ``[Web Page] --postMessage--> [Content Script] --chrome.runtime--> [Background]``
+ 注：通常Content Script会验证消息来源，所以恶意页面通常无法直接利用 postMessage 发送消息到插件，除非插件设计不当。

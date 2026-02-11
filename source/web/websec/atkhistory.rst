通讯方式
========================================

初期阶段：表单提交与页面刷新
----------------------------------------

页面导航跳转
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 场景
    - 传统多页面应用
    - 文件上传（必须用表单）
    - 简单的页面跳转
    - SEO友好的内容页面
+ 特点
    - 同步阻塞操作
    - 整页完全刷新
    - 浏览器历史记录更新
    - 简单直接，无需JavaScript
+ 请求类型
    - ``GET：<a href="...">``
    - ``POST/GET：<form method="POST/GET">``
+ 数据格式
    - ``GET：查询字符串 ?key=value&key2=value2``
    - ``POST：application/x-www-form-urlencoded 或 multipart/form-data``
+ 头部自动设置
    ::

        # 链接点击
        Accept: text/html,application/xhtml+xml,application/xml
        Accept-Language: zh-CN,zh;q=0.9
        Upgrade-Insecure-Requests: 1

        # 表单提交
        Content-Type: application/x-www-form-urlencoded
        # 或对于文件上传
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryxxx
+ 缺点：每次提交表单都会导致页面刷新，用户体验较差。

资源引用加载
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 场景
    - 加载页面所需的静态资源（如图片、CSS、JavaScript 文件等）
+ 特点
    - 浏览器自动发起
    - 并行加载（HTTP/1.1有限制）
    - 缓存机制完
    - 跨域策略各异
+ 各种资源的头部特点
    - ``<script> -> Accept: */*`` : 支持CORS，可跨域
    - ``<link> -> Accept: text/css`` :可跨域
    - ``<img> -> Accept: image/*`` : 可跨域
    - ``<iframe>`` : 完整页面请求头,同源限制严格

安全威胁1
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 安全基础： 同源策略
+ 常见攻击
    - CSRF（跨站请求伪造）
    - XSS（跨站脚本攻击）
    - Clickjacking（点击劫持）

XMLHttpRequest (XHR) - AJAX 核心
----------------------------------------

AJAX
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ AJAX（Asynchronous JavaScript and XML）允许在 **不刷新页面（异步）** 的情况下与服务器进行通信。
+ 默认 **不支持跨域** 请求，需配合 CORS 使用。
+ 组成原理
    - XMLHttpRequest：用于在后台与服务器交换数据。
    - JavaScript：用于处理响应并更新网页内容。
    - XML 或 JSON：作为数据交换格式（现代应用中，JSON 更为流行）。
+ 浏览器自动设置的头部
    ::

        # 默认头部
        X-Requested-With: XMLHttpRequest
        Accept: application/json, text/javascript, */*; q=0.01
        Origin: https://当前域名

        # 根据数据类型自动设置
        Content-Type: text/plain;charset=UTF-8  # 发送字符串时
        # 如果设置了xhr.setRequestHeader('Content-Type', ...)则使用自定义值

jQuery
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ jQuery 是一个流行的 JavaScript 库，简化了 AJAX 请求的编写。

安全威胁
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 安全机制
    - 同源策略
    - CORS（跨域资源共享）
    - SameSite、Content-Type检查
+ 常见攻击
    - CSRF（跨站请求伪造）
    - XSS（跨站脚本攻击）
    - JSON劫持
    - CORS滥用

Fetch API（现代标准）
----------------------------------------

fetch API
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ Fetch API 是现代浏览器中用于发起网络请求的接口，基于 Promise，语法更简洁。
+ 自动设置的头部
    ::

        # 默认请求头
        Accept: */*
        Accept-Language: zh-CN,zh;q=0.9
        Sec-Fetch-Mode: cors
            cors	跨域请求，期望CORS检查	fetch('https://api.com')
            navigate	页面导航请求	点击链接、地址栏输入
            no-cors	不需要CORS的跨域请求（如图片）	<img src="...">
            same-origin	同源请求，不允许跨域	fetch('/api', {mode: 'same-origin'})
            websocket	WebSocket连接请求	new WebSocket('wss://...')
        Sec-Fetch-Site: same-origin
            same-origin	完全同源请求	app.com → app.com/api
            same-site	同站但不同源（相同eTLD+1）	blog.app.com → api.app.com
            cross-site	完全跨站请求	evil.com → bank.com/api
            none	    浏览器直接发起的请求（如地址栏输入）	直接访问 bank.com

        # 根据body类型自动设置
        # 发送JSON时
        Content-Type: application/json

        # 发送FormData时
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryxxx

        # 发送URLSearchParams时
        Content-Type: application/x-www-form-urlencoded;charset=UTF-8

+ 缺点
    - fetch 不会自动处理 HTTP 请求中的错误状态码（如 404 或 500），需要开发者手动处理。
    - fetch 的默认行为 **不支持跨域请求时的 Cookie** ，因此需要手动设置 credentials 选项。

axios
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ Axios 是一个基于 Promise 的 HTTP 客户端，支持浏览器和 Node.js 环境。

安全威胁2
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 安全机制
    - CSP
    - CORP
    - COOP/COEP
    - Fetch Metadata
+ 常见攻击
    - XSS
    - CORS配置错误
    - Spectre类攻击
HTTP状态码与安全测试
==================================

Informational (1xx)
----------------------------------
+ 100 / 101 — 很少直接利用。主要涉及握手层行为（如协议升级）。注意：101 Switching Protocols 在 WebSocket 协商过程中可能出现。

Successful (2xx)
----------------------------------
+ 200 OK — 正常返回资源。但需警惕：若本应是登录页面或管理路径（如 /admin）返回 200，可能暗示访问控制缺陷或认证检查失效。
   - 测试：执行 curl -i https://target.tld/admin 并观察响应体和响应头。
+ 204 No Content — API 端点无返回体时有用；可能隐藏了状态变更成功的信息——需检查其副作用。

Redirection (3xx)
----------------------------------
+ 301 / 302 / 307 / 308 — 需确认重定向行为。重点关注：开放重定向或不安全的 Location 值（是否用户可控）。
   - 开放重定向测试：curl -I "https://target.tld/redirect?next=https://evil.com"
   - 若 Location 回显了攻击者的 URL，则存在开放重定向漏洞（可被用于钓鱼或SSRF攻击链）。
+ 304 Not Modified — 反映缓存行为；通常不可直接利用，但有信息价值。

Client Error (4xx)
----------------------------------
+ 400 Bad Request — 可能泄露解析逻辑。利用场景：参数模糊测试时，不同Payload导致400与200的差异，可辅助构造利用字符串。
+ 401 Unauthorized — 表示需要认证。若移除Cookie后端点仍返回200，可能存在认证绕过。
+ 403 Forbidden — 明确拒绝访问。但有趣的现象：登录用户看到403而匿名用户看到200，可能表明基于角色的配置错误。此外，有时对 OPTIONS 或 HEAD 请求返回的403会携带有用头部信息。
+ 404 Not Found — 信息搜集常用。多数扫描器依赖404特征。自定义404页面可能泄露服务器类型或堆栈跟踪信息。
+ 405 Method Not Allowed — 务必测试其他HTTP方法（PUT、DELETE、TRACE、OPTIONS）。其中，TRACE/PUT 的配置缺陷可能被利用。
+ 409 Conflict / 410 Gone — 较少见，但可能揭示资源生命周期或竞争条件。
+ 429 Too Many Requests — 命中速率限制。对自动化测试至关重要，需寻找绕过方法（如伪造IP头部、切换账户、轮换Cookie/令牌）。

Server Error (5xx)
----------------------------------
+ 500 Internal Server Error — 可能泄露服务器错误信息（如堆栈跟踪）。利用场景：通过特制输入触发500错误，观察响应体中的敏感信息。
+ 502 Bad Gateway / 503 Service Unavailable — 可能指示后端服务不可用或过载。利用场景：通过大量请求或特定输入触发503，观察是否存在资源耗尽或DoS攻击面。
+ 504 Gateway Timeout — 可能表明后端服务响应缓慢。利用场景：通过特定输入触发504，观察是否存在资源耗尽或DoS攻击面。   
+ 505 HTTP Version Not Supported — 罕见，但可能指示服务器对特定HTTP版本的处理不当。利用场景：发送不常用的HTTP版本（如HTTP/2）观察响应行为。
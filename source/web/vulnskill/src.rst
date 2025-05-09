SRC漏洞挖掘思路
========================================

确定目标
----------------------------------------
+ 专属SRC

测试范围
----------------------------------------
+ 通过SRC活动页面，查看测试目标域名范围
+ 爱企查获取公司所属域名
    搜索想要测试等SRC所属公司名称，在知识产权->网站备案中可以获取测试范围。

子域名
----------------------------------------
+ 使用oneforall扫描获取子域名

系统指纹探测
----------------------------------------
+ 使用Ehole
+ 使用Glass

框架站点漏洞测试
----------------------------------------
+ Nday漏洞

非框架型站点漏洞测试
----------------------------------------
+ 登录框
    - 用户名枚举
    - 验证码绕过/置空
    - 暴力破解
    - 自行注册

端口扫描
----------------------------------------
+ ``sudo nmap -sS -Pn -n --open --min-hostgroup 4 --min-parallelism 1024 --host-timeout 30 -T4 -v  examples.comsudo nmap -sS -Pn -n --open --min-hostgroup 4 --min-parallelism 1024 --host-timeout 30 -T4 -v -p 1-65535 examples.com``

目录扫描
----------------------------------------
+ ``python3 dirsearch.py -u www.xxx.com -e * -t 2``

JS信息搜集
----------------------------------------
+ JSFinder

小程序/公众号
----------------------------------------
+ 小程序抓包、APP抓包参考链接：
    ::
    
        https://mp.weixin.qq.com/s/xuoVxBsN-t5KcwuyGpR56g
        https://mp.weixin.qq.com/s/45YF4tBaR-TUsHyF5RvEsw
        https://mp.weixin.qq.com/s/M5xu_-_6fgp8q0KjpzvjLg
        https://mp.weixin.qq.com/s/Mfkbxtrxv5AvY-n_bMU7ig

思路清单
----------------------------------------

信息搜集与资产发现
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ C段扫描
    - 使用ffuf+自写脚本对C段进行批量目录扫描，部署在VPS上后台运行，保存扫描结果。
+ JS文件泄露API接口
    - 通过JS文件泄露的API接口，拼接base路径，批量访问，获取用户名规则，生成用户名字典进行喷洒。
+ Google黑语法
    - 使用Google黑语法搜寻学号、默认密码等敏感信息。
+ Github语法
    - 通过Github语法查找CMS源码、项目源码、敏感信息。
+ 前端泄露调试器
    - 全局搜索key、security、ak、sk、password、username等敏感信息。
+ F12 
    - XHR截取异步流量：获取请求的API接口信息。

文件上传漏洞
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ FUZZ上传参数
    - 对upload.php空白界面FUZZ参数名，爆破参数值，出现上传表单后上传shell。
+ 绕过文件类型检测
    - 修改type、fileType、breach等参数为0、1、2或all，绕过文件类型检测，上传成功。
+ IE上传绕过
    - 用IE打开上传点，上传马子，通过filename="1.asp";filename="1.jpg"绕过检测。

XSS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ WAF绕过
    - 输出在JS内的闭合与注释；使用Function()代替eval()；atob解密base64加密的JS，绕过对alert()的过滤；反引号代替括号与引号，绕过对()的过滤。
+ 存储型XSS与换绑验证码组合
    - 通过存储型XSS与换绑的验证码输出在前端的组合，实现任意账户无感换绑。

SSRF漏洞
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ FUZZ目录与参数名
    - 通过FUZZ目录、参数名得到/xxx?image_url=xx，直接无脑get一个SSRF漏洞。
+ 修改imageurl参数
    - 将imageurl参数修改为dnslog地址，探测内网或云服务器元数据。

逻辑漏洞
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ **水平越权** :删除openid参数获取所有用户信息，用得到的账号用户名进行喷洒，成功登录。
+ **任意用户密码重置** :登录接口遍历手机号，密码重置时将手机号替换为其他手机号，成功重置密码。
+ **认证缺陷** :遍历id获得多个手机号，openid使用手机号做唯一的身份校验。
+ **订单信息泄露** :输入手机号获取对应订单信息，滞空手机号返回所有用户信息。
+ **管理员token获取** :修改username参数为admin，返回管理员token，复用此凭证访问敏感接口。
+ **弱cookie问题** :修改cookie的UserCode值为admin，直接获得管理员权限，尝试SQL注入成功。
+ **A站点泄露B站点信息** :A站点接口泄露B站点的URL、用户名、密码，直接调用B站点数据。
+ **日志扫描** ：通过日志中的IP进行大量扫描活动，找到上传点，上传ASPX马，通过目录遍历漏洞getshell。
+ **修改POST参数** ：修改POST参数username为admin获得管理员权限，重置管理员密码。
+ **并发漏洞** ：通过并发漏洞进行重放攻击。
+ **前端校验数据伪造** ：前端校验数据伪造导致的各种问题。
+ **用户名枚举** ：使用fuzz模块生成二到三位的简单用户名，或使用TOP中文名汉字字典。
+ **优惠券多次复用** ：尝试多次复用优惠券。
+ **购买售罄商品** ：尝试购买售罄的商品。
+ **参数遍历** ：通过参数遍历寻找隐藏商品、赠品、附属商品，实现0元购。
+ **越权测试** ：注册两个账号进行越权测试。
+ **响应包长度分析** ：分析响应包长度，寻找最大、最小、临界值。
+ **未授权接口寻找** ：通过FUZZ、405改请求方法、5xx错误寻找未授权接口。
+ **403 Bypass** ：通过FUZZ爆破次级目录或403 Bypass绕过限制。
+ **密码爆破绕过** ：横向爆破用户名，或通过虚假锁定绕过密码爆破限制。
+ **校验过程与处理过程分离** ：通过一次校验后，跳过校验过程直接进行处理过程。
+ **验证码未绑定** ：只校验验证码是否有效，导致任意用户登录。
+ **NULL情况未考虑** ：验证码可删除绕过校验。
+ **输入校验过滤不严** ：导致二次注入、二次XSS。
+ **MySQL数据截断** ：insert into数据长度溢出时截断数据，导致注册时的任意用户覆盖。
+ **流程凭证未绑定账号信息** ：导致任意有效流程凭证可复用，实现任意用户密码重置。
+ **密保问题简单可猜解** ：通过简单猜解密保问题绕过验证。
+ **验证码回显在set-cookie中** ：通过set-cookie中的验证码回显绕过验证。
+ **万能、默认验证码** ：使用万能或默认验证码绕过验证。
+ **未使用的token不过期** ：导致任意用户越权操作。
+ **token可猜解** ：通过猜解或预测token实现任意用户越权操作。
+ **邮箱密码重置链接凭证不绑定账号** ：通过修改账号ID实现任意用户密码重置。
+ **账号激活链接未加密** ：通过构造激活链接实现任意用户注册。
+ **pid作为唯一校验参数** ：通过roleid替换pid遍历用户凭证，获取更多信息。
+ **userGroupId遍历** ：通过遍历userGroupId以更高权限注册，提升权限。
+ **404僵局打破** ：通过爆出目录打破404僵局，发现SSRF漏洞。
+ **递归FUZZ登录接口** ：通过递归FUZZ得到登录接口，滞空密码免密登录。
+ **管理员账号密码重置** ：通过简单密保问题爆破重置管理员密码。
+ **司机身份越权** ：通过司机身份获取用户订单，替换订单号取消订单。
+ **session_key泄漏** ：通过session_key和iv解密encrypteData参数，越权篡改数据，实现任意账号登录。
+ **DDOS攻击** ：通过修改查询范围，拉满处理能力，达到拒绝服务效果。

其他漏洞
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ **前端数据截图伪造** ：通过前端数据截图伪造与水平越权数据泄露的组合，实现退款欺骗。
+ **OAuth缺陷** ：通过OAuth缺陷实现CSRF任意用户换绑，接管任意用户。
+ **四舍五入数据处理不当** ：导致支付逻辑漏洞或越权逻辑漏洞。
+ **前端校验关键数据** ：前端校验关键数据（如手机号）导致任意换绑，实现任意用户密码重置。
+ **弱cookie导致的任意用户伪造** ：通过弱cookie篡改实现任意用户伪造。
+ **验证码4-5位可爆破** ：通过爆破4-5位验证码绕过验证。
+ **验证码回显在响应包中** ：通过响应包中的验证码回显绕过验证。
+ **未使用的token不过期** ：未使用的token不过期，且不包含用户凭证信息，导致任意用户越权操作。
+ **token可猜解** ：通过猜解或预测token实现任意用户越权操作。
+ **邮箱密码重置链接凭证不绑定账号** ：通过修改账号ID实现任意用户密码重置。
+ **账号激活链接未加密** ：通过构造激活链接实现任意用户注册。
+ **pid作为唯一校验参数** ：通过roleid替换pid遍历用户凭证，获取更多信息。
+ **userGroupId遍历** ：通过遍历userGroupId以更高权限注册，提升权限。
+ **404僵局打破** ：通过爆出目录打破404僵局，发现SSRF漏洞。
+ **递归FUZZ登录接口** ：通过递归FUZZ得到登录接口，滞空密码免密登录。
+ **管理员账号密码重置** ：通过简单密保问题爆破重置管理员密码。
+ **司机身份越权** ：通过司机身份获取用户订单，替换订单号取消订单。
+ **session_key泄漏** ：通过session_key和iv解密encrypteData参数，越权篡改数据，实现任意账号登录。
+ **DDOS攻击** ：通过修改查询范围，拉满处理能力，达到拒绝服务效果。


推荐网站
----------------------------------------
+ 包含SRC通道和在线工具：https://index.tesla-space.com/
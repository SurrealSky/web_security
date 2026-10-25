安卓APP
========================================

一般流程
----------------------------------------
+ 信息收集
+ 漏洞挖掘
+ 漏洞利用
+ getshell
+ 提权
+ 权限维持
+ 清理痕迹
+ 撰写报告总结

攻击面
----------------------------------------

四大组件
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 四大组件（Activity、Service、Broadcast Receiver、Content Provider）通过 AndroidManifest.xml 中的 android:exported 属性决定是否对外暴露。
+ 单纯 "组件导出" 本身通常不被 SRC 视为有效漏洞，需要证明可触达敏感操作——例如通过导出的 Activity 绕过认证、通过导出的 Provider 读取用户 Token 或数据库、通过导出的 Broadcast Receiver 触发短信发送或账户变更。

WebView 与混合应用桥接
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 最典型的链式路径是：DeepLink → WebView 加载不可信 URL → JSBridge 方法被恶意 JavaScript 调用。

本地存储与文件系统：物理访问与同设备攻击场景
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 本地存储攻击面的价值高度依赖攻击模型。在 SRC 中，如果要求攻击者具备物理接触设备或 root 权限，很多厂商会降低评级；
+ 但同设备恶意应用场景下的存储问题仍然有效，尤其是当应用之间通过共享存储或不当的 ContentProvider / FileProvider 交互时。

动态代码加载与 Native 层
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 动态代码加载的风险:应用通过 DexClassLoader 或 dlopen 从外部路径（可写目录、未校验的下载源）加载代码。如果加载源可被攻击者控制（例如通过路径穿越写入应用私有目录，或通过不安全的热更新通道劫持下载），就可以实现代码注入。
+ Native 层（JNI / .so） 的风险:JNI 函数对 Java 传入的数组/字符串长度不做校验导致的越界，FindClass / GetMethodID 使用来自外部输入的类名/方法名，以及 native 回调 Java 时的类型混淆。

供应链与 SDK
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 一个 SDK 中的 Intent 重定向或组件导出缺陷，可能影响集成该 SDK 的成千上万款应用。

SRC挖掘优先级
----------------------------------------
+ 先做暴露面枚举（Manifest + 组件 + DeepLink/WebView）
+ 围绕业务逻辑做数据流追踪（抓包 + 鉴权分析）
+ 最后根据目标类型决定是否下沉到 Native/动态加载。

相关工具
----------------------------------------
- Drozer
- Intent Sniffer
- Intent Fuzzer
- Android Security Evaluation Framework (ASEF)
- AFE(Android Framework for Exploitation)
- X-Ray
- Smartphone Pentest Framework (SPF)
- dSploit(nowadays, dSploit merges with zANTI2)


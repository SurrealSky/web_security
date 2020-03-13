数据库检测
================================

acess
--------------------------------
- ``and exists (select * from msysobjects ) > 0``

MySQL
--------------------------------
- sleep ``sleep(1)``
- benchmark ``BENCHMARK(5000000, MD5('test'))``
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
--------------------------------
- 字符串连接 
    - ``select 'ab'='a'||'b'``
    - ``select 'ab'=CONCAT('a','b')``
- version 
    - ``SELECT banner FROM v$version``
    - ``SELECT banner FROM v$version WHERE rownum=1``
- 数字函数
	- ``BITAND(1,1)``

SQLServer
--------------------------------
- WAITFOR ``WAITFOR DELAY '00:00:10';``
- SERVERNAME ``SELECT @@SERVERNAME``
- version ``SELECT @@version``
- 字符串连接
	- ``select 'a'+'b'='ab'``
- 常量
    - ``@@pack_received``
    - ``@@rowcount``
- ``and exists (select * from sysobjects ) > 0``

PostgreSQL
--------------------------------
- sleep ``pg_sleep(1)``
- ``select version()``
- ``select 'ab'='a'||'b'``
- ``select 'ab'=CONCAT('a','b')``
- ``SELECT EXTRACT(DOW FROM NOW())``

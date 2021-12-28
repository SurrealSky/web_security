模糊测试
----------------------------------------

Web Fuzz
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `ffuf <https://github.com/ffuf/ffuf>`_
	+ 基本攻击：``ffuf -u host/FUZZ -w dict.txt``
	+ 多字典攻击：``ffuf --u host/FUZZ1/FUZZ2 -w dict.txt:FUZZ1 -w dict.txt:FUZZ2``
	+ 添加cookie：``-b COOKIE_VALUE``
	+ 静默模式：``-s``
	+ 指定拓展名：``-e``
	+ POST参数：``ffuf -request test.txt -request-proto http -mode clusterbomb -w user.txt:FUZZ1 -w pass.txt:FUZZ2``
	+ 匹配http状态码：``-mc status-code``
	+ 匹配lines：``-ml lines``
	+ 匹配字数：``-mw 字数``
	+ 匹配大小：``-ms size``
	+ 匹配正则：``-mr value``
	+ 过滤http状态码：``-fc status-code``
	+ 过滤lines：``-fl lines``
	+ 过滤长度：``-fs size``
	+ 过滤字数：``-fw words``
	+ 过滤正则：``-fr value``
	+ 增加颜色：``-c``
	+ 延迟：``-p 延迟多长时间``
	+ 详细模式：``-v``
	+ 线程：``-t``
	
- `wfuzz <https://github.com/xmendez/wfuzz>`_
	+ ``字典路径：/usr/share/wfuzz/wordlist`` 
	+ ``子域爆破：wfuzz -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -H "Host: FUZZ.votenow.local" --hw 854 --hc 400 votenow.local``
	+ ``爆破文件：wfuzz -w /usr/share/wordlists/wfuzz/general/megabeast.txt --hc 404 http://172.16.100.102/FUZZ.sh`` 
	+ ``爆破目录：wfuzz -w wordlist http://192.168.91.137/FUZZ`` 
	+ ``枚举参数值：wfuzz -z range,000-999 http://127.0.0.1/getuser.php?uid=FUZZ`` 
	+ ``爆破HTTP表单：wfuzz -w userList -w pwdList -d "username=FUZZ&password=FUZ2Z" http://127.0.0.1/login.php`` 
	+ ``携带cookie：wfuzz -z range,000-999 -b session=session -b cookie=cookie http://127.0.0.1/getuser.php?uid=FUZZ`` 
	+ ``指定HTTP头：wfuzz -z range,0000-9999 -H "X-Forwarded-For: FUZZ" http://127.0.0.1/get.php?userid=666`` 
	+ ``HTTP请求方法：wfuzz -z list,"GET-POST-HEAD-PUT" -X FUZZ http://127.0.0.1/`` 
		::
		
			-z list可以自定义一个字典列表（在命令中体现），以-分割；
			-X参数是指定HTTP请求方法类型，因为这里要测试HTTP请求方法，后面的值为FUZZ占位符。
	+ ``使用代理：wfuzz -w wordlist -p 127.0.0.1:1087:SOCKS5 URL/FUZZ`` 
	+ ``--hc/hl/hw/hh N[,N]+：隐藏指定的代码/行/字/字符的responsnes。`` 
		::
		
			wfuzz -w megabeast.txt --hc=404 http://192.168.91.133/FUZZ
	+ ``--hs regex：在响应中隐藏具有指定正则表达式的响应。`` 
	+ ``zip并列迭代：wfuzz -z range,0-9 -w dict.txt -m zip http://127.0.0.1/ip.php?FUZZ=FUZ2Z`` 
		::
		
			设置了两个字典。两个占位符，一个是range模块生成的0、1、2、3、4、5、6、7、8、
			9,10个数字，一个是外部字典dict.txt的9行字典，使用zip迭代器组合这两个字典发送。
			zip迭代器的功能：字典数相同、一一对应进行组合，如果字典数不一致则多余的抛弃
			掉不请求，如上命令结果就是数字9被抛弃了因为没有字典和它组合。
	+ ``chain组合迭代：wfuzz -z range,0-9 -w dict.txt -m chain http://127.0.0.1/ip.php?FUZZ`` 
		::
		
			设置了两个字典，一个占位符FUZZ，使用chain迭代器组合这两个字典发送。
			这个迭代器是将所有字典全部整合（不做组合）放在一起然后传入占位符FUZZ中。
			顺序19种。
	+ ``product交叉迭代：wfuzz -z range,0-2 -w dict.txt -m product http://127.0.0.1/ip.php?FUZZ=FUZ2Z`` 
		::
		
			设置了两个字典，两个占位符，一个是range模块生成的0、1、2这3个数字，一个是外部字典
			dict.txt的3行字典，使用product迭代器组合这两个字典发送，9种组合。
	+ ``使用Encoders：wfuzz -z file --zP fn=wordlist,encoder=md5 URL/FUZZ`` 
		::
		
			简写命令：wfuzz -z file,wordlist,md5 URL/FUZZ
	+ ``组合Encoder：wfuzz -z file,dict.txt,md5-base64 http://127.0.0.1/ip.php\?FUZZ`` 
		::
		
			多个转换，使用一个-号分隔的列表.
			相当于组合，分别进行MD5模糊，和base64模糊测试。
	+ ``多次Encoder：wfuzz -z file,dict.txt,base64@md5 http://127.0.0.1/ip.php\?FUZZ`` 
		::
		
			多次转换，使用一个@号分隔的列表.
			按照从右往左顺序对字典数据进行多次转换。
	+ 注：FUZZ位置即为需要模糊测试。
- `SecLists <https://github.com/danielmiessler/SecLists>`_
- `fuzzdb <https://github.com/fuzzdb-project/fuzzdb>`_
- `foospidy payloads <https://github.com/foospidy/payloads>`_

Unicode Fuzz
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `utf16encode <http://www.fileformat.info/info/charset/UTF-16/list.htm>`_

WAF Bypass
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `abuse ssl bypass waf <https://github.com/LandGrey/abuse-ssl-bypass-waf>`_
- `wafninja <https://github.com/khalilbijjou/wafninja>`_

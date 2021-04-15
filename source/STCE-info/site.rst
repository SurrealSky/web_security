站点信息
========================================

- 判断网站操作系统
    - Linux大小写敏感
    - Windows大小写不敏感
- 扫描敏感文件
    - robots.txt
    - crossdomain.xml
    - sitemap.xml
    - xx.tar.gz
    - xx.bak
    - 等
- 确定网站采用的语言
    - 如PHP / Java / Python等
    - 找后缀，比如php/asp/jsp
- 前端框架
    - 如jQuery / BootStrap / Vue / React / Angular等
    - 查看源代码
- 中间服务器
    - 如 Apache / Nginx / IIS 等
    - 查看header中的信息
    - 根据报错信息判断
    - 根据默认页面判断
- Web容器服务器
    - 如Tomcat / Jboss / Weblogic等
- 后端框架
    - 根据Cookie判断
    - 根据CSS / 图片等资源的hash值判断
    - 根据URL路由判断
        - 如wp-admin
    - 根据网页中的关键字判断
    - 根据响应头中的X-Powered-By
- CDN信息
    - 常见的有Cloudflare、yunjiasu
- 探测有没有WAF，如果有，什么类型的
    - 有WAF，找绕过方式
    - 没有，进入下一步
- 确定网站绝对路径
	- WEB默认目录
		+ Apache
			``Windows：C:\wamp64\www\(Wamp Server)、C:\xampp\htdocs\(XAMPP)、C:\Program Files\Apache Software Foundation\Apachex.x\htdocs\``
			``Linux：/opt/lampp/htdocs(LAMPP)、/var/www/``
		+ IIS
			``C:\inetpub\wwwroot\``
	- SQL注入点暴路径
	- 查询特殊变量
		+ ``secure_file_priv,general_log_file``
		+ ``select @@VARIABLE_NAME或者 show variables like "VARIABLE_NAME"``
	- 暴phpinfo信息
	- Phpmyadmin暴路径
		+ 在获取Phpmyadmin界面后，可以尝试访问以下子目录，某些版本可能会暴出网站路径信息.
		+ /phpmyadmin/libraries/lect_lang.lib.php
		+ /phpmyadmin/index.php?lang[]=1
		+ /phpmyadmin/phpinfo.php
		+ /phpmyadmin/libraries/select_lang.lib.php
		+ /phpmyadmin/libraries/lect_lang.lib.php
		+ /phpmyadmin/libraries/mcrypt.lib.php
	- CMS暴路径
		+ WordPress
			``/wp-admin/includes/file.php``
			``/wp-content/themes/twentynineteen/footer.php``
		+ DedeCMS
			``/member/templets/menulit.php``
			``/plus/paycenter/alipay/return_url.php``
			``/paycenter/nps/config_pay_nps.php``
		+ ECShop
			``/api/cron.php``
			``/wap/goods.php``
			``/temp/compiled/pages.lbi.php``
			``/temp/compiled/admin/login.htm.php``
	- 查看配置文件
		+ Windows
			``Wamp Server：C:\wamp64\bin\apache\apache2.4.37\conf\httpd.conf``
			``XAMPP：C:\xampp\apache\conf\httpd.conf``
			``IIS：6.0版本之前配置文件在C:\windows\system32\inetsrv\metabase.xml，之后配置文件在C:\windows\system32\inetsrv\config\applicationhost.config``
		+ Linux
			``LAMPP：/opt/lampp/etc/httpd.conf``
			``Apache：/etc/httpd/conf/httpd.conf``
			``PHP：/etc/php.ini``

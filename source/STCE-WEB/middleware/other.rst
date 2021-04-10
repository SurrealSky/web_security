其它
========================================

Tornado
----------------------------------------

Zope
----------------------------------------

tomcat
----------------------------------------
- Apache和Tomcat的区别
	+ Apache只是一个普通服务器，只能用来解析静态页面（html），不支持解析动态页面（jsp），它可以通过插件支持php。
	+ 解析动态页面（jsp）要用到Tomcat，Tomcat同时也支持HTML、JSP、ASP、PHP、CGI等。
	+ Apache是用C语言实现的，支持各种特性和模块从而来扩展核心功能，而Tomcat是用Java实现的，所以它更好的支持jsp。
	+ 一般使用Apache+Tomcat的话，Apache直接处理静态请求而不经过Tomcat，对于动态请求，Apache只是作为一个转发，对jsp的处理是由Tomcat来处理的，Apache回传解析好的静态代码，这样整合就可以减少Tomcat的服务开销。 
	+ Apache可以单向与Tomcat连通，就是说通过Apache可以访问Tomcat资源，反之不然。
	+ 从本质上来说Tomcat的功能完全可以替代Apache，但Apache虽然不能解析Java的东西，但解析html速度快，不会被取代。
	+ Apache可以运行一年不重启，稳定性非常好。
	+ 首选web服务器是Apache，但Apache解析不了的jsp、servlet才用Tomcat。
	+ 只使用Apache服务器不需要安装jdk，使用Tomcat服务器必须安装jdk并配置好环境变量。

lighttd
----------------------------------------



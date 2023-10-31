基本概念
========================================

三个平台
----------------------------------------
+ Java SE（Java平台标准版）
+ Java EE（Java平台企业版）
    - 应用最广泛得版本，成为J2EE，是Sun公司为企业级应用推出的标准平台
    - 用于开发B/S架构软件
+ Java ME（Java平台微型版）

JVM
----------------------------------------
JVM是Java平台的核心，以机器代码来实现，为程序执行提供了所需的所有基本功能，例如字节码解析器、JIT编译器、垃圾收集器等。由于它是机器代码实现的，其同样受到二进制文件受到的攻击。

JCL是JVM自带的一个标准库，含有数百个系统类。默认情况下，所有系统类都是可信任的，且拥有所有的特权。

JDK
----------------------------------------
Java开发工具包（Java Development Kit，JDK）是Oracle公司发布的Java平台，有标准版（Standard Edition，Java SE）、企业版（Enterprise Edition，Java EE）等版本。

在最开始，JDK以二进制形式发布，而后在2006年11月17日，Sun以GPL许可证发布了Java的源代码，于是之后出现了OpenJDK。

JMX
----------------------------------------
JMX（Java Management Extensions，Java管理扩展）是一个为应用程序植入管理功能的框架。

OGNL
----------------------------------------
OGNL（Object-Graph Navigation Language，对象导航语言）是一种功能强大的表达式语言，通过简单一致的表达式语法，提供了存取对象的任意属性、调用对象的方法、遍历整个对象的结构图、实现字段类型转化等功能。

Struts2中使用了OGNL，提供了一个ValueStack类。ValueStack分为root和context两部分。root中是当前的action对象，context中是ActionContext里面所有的内容。

识别
----------------------------------------
+ .JSP:用于标准的JSP文件
+ .do或者.action，用于MVC框架。
+ .json 用于提供Json数据的Restful接口。
+ Servlet可以不用后缀。
+ .html：用于伪静态，或者真静态。 

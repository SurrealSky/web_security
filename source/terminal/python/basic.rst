基础
========================================

运行原理
----------------------------------------
+ 把原始代码编译成字节码（.pyc文件不一定会落盘）
+ 把编译好的字节码转发到Python虚拟机（PVM）中进行执行

文件类型
----------------------------------------

打包原理
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 运行过程
	- Python.exe调用XX.py(源码)，解释并运行。
	- Python.exe调用XX.pyc(字节码)，解释并运行。
	- Python.exe调用XX.pyd(机器码)，调用运行。
	- 如果有依赖的库，根据上面三种情况调用运行。
+ 分析脚本文件，递归找到所有依赖的模块。如果依赖模块有.pyd文件，即将其复制到disk目录。如果没有.pyd文件，则生成.pyc文件拷贝到disk目录，并压缩为.zip保存。制作一个exe，导入PythonXX.dll(解析器库)，并添加exe运行需要的相关运行时库。这就构成了一个不用安装Python的运行包。

pyc文件
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ pyc文件是Python编译后的字节码文件，包含了Python源代码的编译结果，可以直接被Python解释器执行。

pyo文件
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ pyo文件是源代码文件经过优化编译后生成的文件，是pyc文件的优化版本，由解释器在导入模块时创建。

pyd文件
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ .pyd文件类型是特定于Windows操作系统类平台的，是一个动态链接库，它包含一个或一组Python模块，由其他Python代码调用。

pyz文件
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ ZlibArchive：executable python zip archives


PyInstaller打包
-----------------------------------------
+ ZlibArchive：包含压缩的.pyc或.pyo文件。
+ CArchive：很像一个.zip文件，可以包含任何类型的文件。可以python创建，也可以从C代码中解包。

pyc反编译
-----------------------------------------
+ uncompyle6
	- 命令： ``uncompyle6 -o test.py test.pyc``
+ pycdc
	- 命令： ``pycdc test.pyc > test.py``
+ 在线工具
	- ``https://tool.lu/pyc/``

exe反编译
-----------------------------------------
+ pyinstxtractor
	- 命令： ``python pyinstxtractor.py test.exe``
+ pyi-archive_viewer
	- 项目地址： ``https://pyinstaller.org/en/stable/advanced-topics.html#using-pyi-archive-viewer``
	- 命令： ``pyi-archive_viewer test.exe``
+ pyinstxtractor-ng
	- 项目地址： ``https://github.com/pyinstxtractor/pyinstxtractor-ng``
	- 命令： ``python pyinstxtractor-ng.py test.exe``
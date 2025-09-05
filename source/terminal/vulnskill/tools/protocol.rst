协议型漏洞FUZZ
----------------------------------------
- `SPIKE <https://resources.infosecinstitute.com/topic/intro-to-fuzzing/>`_
	C语言实现开源，支持windows和linux系统。
- beSTORM
- `Fuzzowski <https://github.com/nccgroup/fuzzowski>`_
- `backfuzz <https://github.com/localh0t/backfuzz>`_
- GANFuzz
- `boofuzz <https://boofuzz.readthedocs.io/en/stable/>`_
	+ 教程：https://paper.seebug.org/1626/
	+ 官方：https://boofuzz.readthedocs.io
	+ 语法风格
		- Spike-style static protocol definition：https://boofuzz.readthedocs.io/en/stable/user/static-protocol-definition.html
		- non-static protocol definition：https://boofuzz.readthedocs.io/en/stable/user/protocol-definition.html
	+ 日志文件
		- 保存在boofuzz-results下的DB文件
		- 重新打开： ``boo open <run-*.db>`` 
	+ web可视化
		- http://127.0.0.1:26000/
- Kitty
	+ 教程：https://paper.seebug.org/772/
- BFuzz
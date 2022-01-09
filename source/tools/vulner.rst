漏洞挖掘
----------------------------------------

固件分析
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- binwalk
	+ 固件扫描:``binwalk firmware.bin``
	+ 提取文件:``binwalk -eM firmware1.bin firmware2.bin firmware3.bin``
	+ 文件比较:``binwalk -W --block=8 --length=64 firmware1.bin firmware2.bin``
	+ 指令系统分析:``binwalk -A firmware.bin``
	+ 熵分析:``binwalk -E firmware.bin``
	+ 插件分析:``binwalk --enable-plugin=zlib firmware.bin``
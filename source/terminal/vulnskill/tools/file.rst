文件型漏洞FUZZ
----------------------------------------
- Peach Fuzzer
	+ Peach支持对 **文件格式、ActiveX、网络协议** 进行Fuzz测试，Peach Fuzz的关键是编写Peach Pit配置文件。
	+ 官网源码：https://gitlab.com/gitlab-org/security-products/protocol-fuzzer-ce
	+ 在线帮助：https://peachtech.gitlab.io/peach-fuzzer-community/WhatIsPeach.html
	+ windows编译：https://zhuanlan.zhihu.com/p/386565953
	+ 打开安装目录PeachService.exe，可以打开web服务，浏览器查看FUZZ进度和崩溃信息
	+ pit文件结构
		- 首先必须创建Peach Pit格式文件，文件是基于XML格式，里面记录了文件格式的组织方式，我们需要如何进行Fuzz，Fuzz的目标等信息。
		- Pit文件主要包含5个元素
			+ DataModel：定义数据结构的元素。
			+ StateModel：管理 Fuzz 过程的执行流。
			+ Agents：监视 Fuzz 过程中程序的行为，可以捕获程序的 crash 信息。
			+ Test Block：将 StateModel 和 Agents 等联系到一个单一的测试用例里。
			+ Run Block：定义 Fuzz 过程中哪些 Test 会被执行。这个块也会记录 Agent 产生的信息。
	+ pit文件基本框架
		::
		
			<?xml version="1.0" encoding="utf-8"?>
			<Peach ...版本，作者介绍之类...>
				<Include ...包含的外部文件/> 			#通用配置
				<DataModel> 					#数据模型
					<Block/>
					<Blob/>
					......
				</DataModel>
				<StateModel> 					#状态模型
				</StateModel> 
				<Agent> 					#代理器
				</Agent>
				<Test>
					<StateModel/> 				#必须
					<Publisher/> 				#必须
					<agent> 				#可选
						<Monitor>
							<Param name="CommandLine" value="test01.exe fuzzed1.png"/> #注意fuzzed1.png与Publisher配置的Filename参数值一致
						</Monitor>
					</agent>
					<Include/> 				#可选
					<Exclude/> 				#可选
					<Strategy/> 				#可选
					<Logger/> 				#可选
						......
			  </Test>
				<Run>Fuzzer执行的进入点</Run>
			</Peach>
	+ 说明
		- publisher="Peach.Agent"
			::
			
				<Action type="call" method="WaitForPort" publisher="Peach.Agent" />
				Peach.Agent即没有指定publisher，默认取Test列表中第一个publisher
	+ 相关示例
		- `文件FUZZ <../../_static/peach_file.xml>`_
		- `UDP协议FUZZ <../../_static/peach_udp.zip>`_
		- `TCP协议FUZZ <../../_static/peach_tcp.zip>`_

- `FileFuzz <https://bbs.pediy.com/thread-125263.htm>`_
- `EasyFuzzer <https://bbs.pediy.com/thread-193340.htm>`_
- `pngcheck <http://www.libpng.org/pub/png/apps/pngcheck.html>`_
- `pdfcheck <https://www.datalogics.com/products/pdf-tools/pdf-checker/>`_
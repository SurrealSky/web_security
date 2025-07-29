COM漏洞
========================================

COM基础
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ COM(微软组件对象模型)，是一种独立于平台的分布式系统，用于创建可交互的二进制软件组件。 
+ COM 是 Microsoft 的 OLE (复合文档) 和 ActiveX (支持 Internet 的组件) 技术的基础技术。
+ 注册表项： ``HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID`` 下，包含COM对象的所有公开的信息。
	::
	
			ProgID ： 代表COM名称
			UUID ： 代表COM
			CLSID ： 代表COM组件中的类
			IID ：代表COM组件中的接口
+ COM组件搜索顺序
	::
	
		HKCU\Software\Classes\CLSID
		HKCR\CLSID
		HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\shellCompatibility\Objects\

分类
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 进程内COM
	- 在DLL中实现的COM/DCOM组件，即In-Process Server，因为这些组件是加载到使用它们的客户端应用程序执行程序内存之中。
	- 当应用程序调用COM/DCOM 组件的服务时，就和一般的程序或函数调用一样，非常快速。
+ 进程外COM
	- 在EXE 中实现的COM/DCOM组件是执行在它自己的执行程序之中，即Out-Process Server。
	- 当客户端应用程序调用在独立的执行程序中的 COM/DCOM 组件时必须穿越不同的执行程序，因为 Out-Process Server 在执行时会比In-Process Server 慢许多。

COM对象的创建
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 脚本语言（VB,JS等）
	::
	
		Dim Shell
		Set Shell = CreateObject("Wscript.Shell")
		Shell.Run "cmd /c calc.exe"
		
		Dim Shell
		Set Shell = GetObject("new:72C24DD5-D70A-438B-8A42-98424B88AFB8")
		Shell.Run "cmd /c calc.exe"
+ html
	::
	
		<object classid=clsid:D45FD31B-5C6E-11D1-9EC1-00C04FD7081F width="32" height="32" name="evil"></OBJECT> 
		<script>
		document.write(evil.OpenPage("cmd.exe"));
		</script>
+ 高级语言（C++等）
	::
	
		#define _WIN32_DCOM
		using namespace std;
		#include <comdef.h>

		#pragma comment(lib, "stdole2.tlb")

		int main(int argc, char** argv)
		{
			HRESULT hres;

			// Step 1: ------------------------------------------------
			// 初始化COM组件. ------------------------------------------

			hres = CoInitializeEx(0, COINIT_MULTITHREADED);

			// Step 2: ------------------------------------------------
			// 初始化COM安全属性 ---------------------------------------

			hres = CoInitializeSecurity(
				NULL,
				-1,                          // COM negotiates service
				NULL,                        // Authentication services
				NULL,                        // Reserved
				RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
				RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
				NULL,                        // Authentication info
				EOAC_NONE,                   // Additional capabilities 
				NULL                         // Reserved
			);
			// Step 3: ---------------------------------------
			// 获取COM组件的接口和方法 -------------------------
			LPDISPATCH lpDisp;
			CLSID clsidshell;
			hres = CLSIDFromProgID(L"WScript.Shell", &clsidshell);
			if (FAILED(hres))
				return FALSE;
			hres = CoCreateInstance(clsidshell, NULL, CLSCTX_INPROC_SERVER, IID_IDispatch, (LPVOID*)&lpDisp);
			if (FAILED(hres))
				return FALSE;
			LPOLESTR pFuncName = L"Run";
			DISPID Run;
			hres = lpDisp->GetIDsOfNames(IID_NULL, &pFuncName, 1, LOCALE_SYSTEM_DEFAULT, &Run);
			if (FAILED(hres))
				return FALSE;
			// Step 4: ---------------------------------------
			// 填写COM组件参数并执行方法 -----------------------
			VARIANTARG V[1];
			V[0].vt = VT_BSTR;
			V[0].bstrVal = _bstr_t(L"cmd /c calc.exe");
			DISPPARAMS disParams = { V, NULL, 1, 0 };
			hres = lpDisp->Invoke(Run, IID_NULL, LOCALE_SYSTEM_DEFAULT, DISPATCH_METHOD, &disParams, NULL, NULL, NULL);
			if (FAILED(hres))
				return FALSE;
			// Clean up
			//--------------------------
			lpDisp->Release();
			CoUninitialize();
			return 1;
		}
+ powershell
	::
	
		通过ProgID创建WSH对象: $shell = [Activator]::CreateInstance([type]::GetTypeFromProgID("WScript.Shell"))
		通过CLSID创建: $shell = [Activator]::CreateInstance([type]::GetTypeFromCLSID("72C24DD5-D70A-438B-8A42-98424B88AFB8"))
		运行：$shell.Run("cmd /c calc.exe")

COM挖掘思路
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 遍历系统COM组件
	::
	
		编写powershell脚本，将CLSID输出到txt文本中：
		New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR
		Get-ChildItem -Path HKCR:\CLSID -Name | Select -Skip 1 > clsids.txt
		利用这些clsid通过powershell创建对应的COM对象，并且使用Get-Member方法获取对应的方法和属性，并最终输出到文本中，pwoershell脚本如下：
		$Position  = 1
		$Filename = "clsid-members.txt"
		$inputFilename = "clsids.txt"
		ForEach($CLSID in Get-Content $inputFilename) {
			  Write-Output "$($Position) - $($CLSID)"
			  Write-Output "------------------------" | Out-File $Filename -Append
			  Write-Output $($CLSID) | Out-File $Filename -Append
			  $handle = [activator]::CreateInstance([type]::GetTypeFromCLSID($CLSID))
			  $handle | Get-Member | Out-File $Filename -Append
			  $Position += 1
		}
+ 自动化FUZZ
	- 使用Fuzz测试工具:比较出名的有ComRaider、Axman等。
+ 人工测试
	- 通过控件解析器如ComRaider 、OLEView等，解析出控件的方法和属性，再根据每个方法的参数和返回值等，手工构造测试用例，依次对各个属性和方法进行异常测试，根据页面的返回情况，确定是否存在安全漏洞。
+ COM劫持攻击
	- 注意
		+ 一般用于后渗透阶段，权限提升，维持等。
		+ 一般两种方法： **寻找被遗弃的COM键进行劫持** ， **覆盖COM对象** 。
	- 寻找被遗弃的COM键进行劫持
		+ 一些程序在卸载后，注册表种的COM键会保留下来，即处于注册的状态，这个COM键会指向一个不存在的DLL文件，可以修改路径实现劫持。
		+ 查找方法
			::
			
				使用promon，以calc.exe为例，使用以下过滤：
				Process Name is calc.exe
				Operation is RegOpenKey
				Result is NAME NOT FOUND
				Path contains InProcServer32
	- 覆盖COM对象
		+ 在HKCU注册表种创建正确的键值，当引用目标COM对象时，HKLM中的键值就会被覆盖（并且“添加”到HKCR中）。

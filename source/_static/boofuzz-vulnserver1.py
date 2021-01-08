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

def test_static():
	tcp_target = Target(connection=TCPSocketConnection(host='192.168.91.134', port=9999))
	session = Session(target=tcp_target,post_test_case_callbacks=[check_response, ping_server],
		crash_threshold_element=20,
		crash_threshold_request=60)

	s_initialize("Request") 
	with s_block("Request-1"):
		#s_group("CMD", ['STATS', 'RTIME', 'LTIME', 'SRUN', 'TRUN', 'GMON', 'GDOG','KSTET','GTER','HTER','LTER','KSTAN'])
		s_static("TRUN")
		s_delim(" ",False)
		s_static("/:./")
		if s_block_start("attack"):
			s_static("AAAAAAAAAAAAAAAA")
			s_block_end("attack")
		s_repeat("attack",max_reps=400)
		
	session.connect(s_get("Request"))
	print(session.num_mutations())
	session.fuzz()

def main():
	test_static();

if __name__ == "__main__":
	main()
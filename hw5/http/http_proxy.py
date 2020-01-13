#! /usr/bin/python3
import socket
import select
import sys
from urllib.parse import *
from email.parser import BytesParser

GET = 'GET '
HTTP1 = ' HTTP/1.1'
HTTP2 = ' HTTP/1.0'
HEADER = "Content-Type"
VULN_PHP = '/interface/forms/eye_mag/taskman.php'
SQLI_FIELDS = ['from_id','to_id', 'pid', 'doc_type', 'enc']
FORBIDDEN_TYPES = ["text/csv", "application/zip"]
C_KEYWORD = ['auto', 'const', 'double', 'float', 'int ', 'int*', 'short ', 'struct ',
	 'unsigned', 'break', 'continue', 'else', 'for', 'long ', 'signed ',
	  'switch', 'void ', 'case', 'defualt', 'enum', 'goto', 'register',
	    'sizeof', 'typedef', 'volatile', 'char ', 'char*', 'do{', 'do \\n{', 'extern', 'if',
		'return', 'static', 'union', 'while', '#define', '*', ';',
	       '#include' , '{', '}', '[', ']', '(', ')', 'print', 'open(',
 		  'close(', 'gets(', 'read(','socket(', 'bind(', 'listen(',
		'main', 'scanf(', 'write(', '||', '&&' ,'~', '->']
line_seperators = [';', ')', '{','}', '&', ',', '|', '"',"'", '>', '\n', '\r']
HTTP_PROXY_PORT = 800
DIR_IN = 1
DIR_OUT = 2
def http_filter(p,  direction):
	try:
		splitted = p.split(b'\r\n', 1)
		request_line = b''
		headers_alone = b''
		if(len(splitted) == 2):
			request_line, headers_alone = splitted
		else:
			request_line = splitted[0]
		headers = BytesParser().parsebytes(headers_alone)
		if(HEADER in headers):
			for t in FORBIDDEN_TYPES:
				if(t in headers[HEADER] and direction == DIR_IN):
					return False
		if(direction == DIR_OUT):
			return sqli_filter(request_line) and c_code_filter(p)
	except Exception as e:
		print(e)
		if(direction == DIR_OUT):
			return c_code_filter(p)
	if(direction == DIR_OUT):
		return c_code_filter(p)
	return True


def sqli_filter(request_line):
	try:
		request_line = request_line.decode('utf-8')
		if(request_line.startswith(GET)):
			request_line = request_line[len(GET):]
		if(request_line.endswith(HTTP1) or request_line.endswith(HTTP2)):
			request_line = request_line[:-len(HTTP1)]
		splitted = urlsplit(request_line)
		fields = parse_qs(splitted.query)
		if(VULN_PHP not in splitted.path):
			return True	
		fields = (parse_qs(splitted.query))
		for f in SQLI_FIELDS:
			if f in fields:
				if not(fields[f][0].isnumeric()):
					print("SQLI in field {}".format(f),"|{}|".format(fields[f][0]))
					return False
		return True
		
	except Exception as e:
		print(e)
		return True	

def c_code_filter(p):
	p = str(p)
#	print(p)
	words = p.split()
	freq_dict = {s:p.count(s) for s in C_KEYWORD}
	total_keywords = sum(freq_dict.values())
	if(len(words) == 0):
		return True
	keyword_rate = total_keywords / len(words)
	if(p.count('\\n') > 0):
		linesep_rate = sum([p.count(s + '\\n') for s in line_seperators]) / p.count('\\n')
		return not(keyword_rate >= 0.5 and linesep_rate >= 0.5)
	return keyword_rate < 0.5


#f1 = '/home/fw/test'

#f2 = "/home/fw/Desktop/hw5/dry.txt"


try:
	in_sock = socket.socket()
	in_sock.bind(("", HTTP_PROXY_PORT))
	in_sock.listen(1)
except:
	print("Could not listen and/or bind")
	sys.exit(-1)
while(True):

	try:
		out_sock = socket.socket()
	except:
		print("Could not create out socket")
		in_sock.close()
		out_sock.close()	
		sys.exit(-1)
	
	try:	
		conn, addr = in_sock.accept()
	except:
		break;
	try:
		out_sock.connect(("10.1.2.2", 80))
	except:
		out_sock.close()
		conn.close()
		continue			
	print("connected to out")
	exit = 0
	while(not exit):
		read, _, _ = select.select([conn, out_sock], [], [conn, out_sock])
		for c in read:
			if(c == conn):
				p = conn.recv(4096)
				if(not(p)):
					read.remove(conn)
					conn.close()
					out_sock.close()
					exit = 1
					break
				if(http_filter(p, DIR_OUT)):
					out_sock.sendall(p)
					read.remove(conn)
			if(c == out_sock):
				p = out_sock.recv(4096)
				if(not(p)):
					read.remove(out_sock)
					out_sock.close()
					conn.close()
					exit = 1
					continue
				if(http_filter(p, DIR_IN)):
					conn.sendall(p)
					read.remove(out_sock)

in_sock.close()
out_sock.close()





#! /usr/bin/python3
import socket
import select
import sys
from email.parser import BytesParser

C_KEYWORD = ['auto', 'const', 'double', 'float', 'int ', 'int*', 'short ', 'struct ',
	 'unsigned', 'break', 'continue', 'else', 'for', 'long ', 'signed ',
	  'switch', 'void ', 'case', 'defualt', 'enum', 'goto', 'register',
	    'sizeof', 'typedef', 'volatile', 'char ', 'char*', 'do{', 'do \\n{', 'extern', 'if',
		'return', 'static', 'union', 'while', '#define', '*', ';',
	       '#include' , '{', '}', '[', ']', '(', ')', 'print', 'open(',
 		  'close(', 'gets(', 'read(','socket(', 'bind(', 'listen(',
		'main', 'scanf(', 'write(', '||', '&&' ,'~', '->']
line_seperators = [';', ')', '{','}', '&', ',', '|', '"',"'", '>', '\n', '\r']
	
SMTP_PROXY_PORT = 250
def smtp_filter(p):
	p = str(p)
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

#f3 = "./smtp_proxy.py"

#with open(f1) as f:
#	p = f.read()
#	smtp_filter(p)		
#sys.exit(0)

try:
	in_sock = socket.socket()
	in_sock.bind(("", SMTP_PROXY_PORT))
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
		out_sock.connect(("10.1.2.2", 25))
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
				if(smtp_filter(p)):
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
				conn.send(p)
				read.remove(out_sock)

in_sock.close()
out_sock.close()





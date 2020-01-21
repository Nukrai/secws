#! /usr/bin/python3
import socket
import select
import sys
from email.parser import BytesParser

C_KEYWORD = ['auto', 'const', 'double', 'float', 'int', 'short', 'struct',
	 'unsigned', 'break', 'continue', 'else', 'for', 'long', 'signed',
	  'switch', 'void', 'case', 'defualt', 'enum', 'goto', 'register',
	    'sizeof', 'typedef', 'volatile', 'char', 'do', 'extern', 'if',
		'return', 'static', 'union', 'while', '#define', '*', ';',
		'#include' , '{', '}', '[', ']', '(', ')']
line_seperators = [';', ')', '{','}', '&', ',', '|', '\n', '\r']
	
STMP_PROXY_PORT = 250
def stmp_filter(p):
	words = p.split()
	freq_dict = {s:p.count(s) for s in C_KEYWORD}
	total_keywords = sum(freq_dict.values())
	print(total_keywords)
	keyword_rate = total_keywords / len(words)
	linesep_rate = sum([p.count(s + '\n') for s in line_seperators]) / p.count('\n')
	print(keyword_rate, linesep_rate)
	return True

f1 = '/home/fw/test'

f2 = "/home/fw/Desktop/hw5/dry.txt"

f3 = "./stmp_proxy.py"

with open(f1) as f:
	p = f.read()
	stmp_filter(p)		
sys.exit(0)

try:
	in_sock = socket.socket()
	in_sock.bind(("", STMP_PROXY_PORT))
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
				if(http_filter(p)):
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
				if(http_filter(p)):
					conn.send(p)
					read.remove(out_sock)

in_sock.close()
out_sock.close()





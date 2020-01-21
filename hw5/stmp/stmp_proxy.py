#! /usr/bin/python3
import socket
import select
import sys
from email.parser import BytesParser

STMP_PROXY_PORT = 250
def stmp_filter(p):
	return True


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





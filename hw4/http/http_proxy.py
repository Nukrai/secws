#! /usr/bin/python3
import socket
import select
import sys
from email.parser import BytesParser

HEADER = "Content-Type"
FORBIDDEN_TYPES = ["text/csv", "application/zip"]
HTTP_PROXY_PORT = 800
def http_filter(p):
	#try:
	print(str(p),"\n\n\n")
	try:
		request_line, headers_alone = p.split(b'\r\n', 1)
		headers = BytesParser().parsebytes(headers_alone)
	except Exception as e:
		return True

	if(HEADER in headers):
		for t in FORBIDDEN_TYPES:
			if(t in headers[HEADER]):
				return False
	return True





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





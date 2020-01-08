#! /usr/bin/python3
import socket
import select
import sys


HTTP_PROXY_PORT = 800
def is_valid():
	return True
try:
	in_sock = socket.socket()
	in_sock.bind(("", HTTP_PROXY_PORT))
	in_sock.listen(1)
except:
	print("Could not listen and/or bind")
	sys.exit(-1)

while True:
	conn, addr = in_sock.accept()
	print(addr)
	try:
		out_sock = socket.socket()
	except:
		print("Could not create out socket")
		in_sock.close()
		out_sock.close()	
		sys.exit(-1)
	try:
		out_sock.connect(("10.1.2.2", 80))
	except:
		out_sock.close()
		in_sock.close()
		sys.exit(-1)
	print("connected to out")
	exit = 0;
	while(not exit):
		read, _, _ = select.select([conn, out_sock], [], [conn, out_sock])
		for c in read:
			if(c == conn):
				p = conn.recv(4096)
				if(not(p)):
					read.remove(conn)
					conn.shutdown(socket.SHUT_RD)
					exit = 1
					continue
				out_sock.sendall(p)
				read.remove(conn)
			if(c == out_sock):
				p = out_sock.recv(4096)
				if(not(p)):
					read.remove(out_sock)
					out_sock.shutdown(socket.SHUT_RD)
					exit = 1
					continue
				conn.send(p)
				read.remove(out_sock)
	conn.close()
	in_sock.close()
	out_sock.close()







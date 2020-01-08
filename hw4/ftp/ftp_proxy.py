#! /usr/bin/python3
import socket
import select
import sys
import os
from email.parser import BytesParser

COMMAND = "PORT "
HOST1_IP = 0x0101010a
HOST2_IP = 0x0202010a
FTP_PROXY_PORT = 210
FTP_PATH = "/sys/class/fw/ftp/ftp"

def ftp_filter(p):
	p = str(p)
	print(p)
	if(COMMAND in p):
		idx = p.index(COMMAND) + len(COMMAND)
		p = p[idx:]
		print(p)
		p = p[:p.index("\\n")]
		ip1, ip2, ip3, ip4, port1, port2 = p.split(",")
		print(port1, port2)
		os.system('echo "{0} {1} {2} {3}" > {4}'.format(HOST2_IP, socket.htons(20), HOST1_IP, socket.htons(16*16*int(port1)+int(port2)) , FTP_PATH))
	print("ftp accepted!")
	return True




try:
	in_sock = socket.socket()
	in_sock.bind(("", FTP_PROXY_PORT))
	in_sock.listen(1)
except:
	print("Could not listen and/or bind")
	sys.exit(-1)

try:
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
			out_sock.connect(("10.1.2.2", 21))
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
					if(ftp_filter(p)):
						out_sock.sendall(p)
						read.remove(conn)
				if(c == out_sock):
					p = out_sock.recv(4096)
					if(not(p)):
						read.remove(out_sock)
						out_sock.shutdown(socket.SHUT_RD)
						exit = 1
						continue
					if(ftp_filter(p)):
						conn.send(p)
						read.remove(out_sock)
except Exception as e:
	print(str(e))
	conn.close()
	in_sock.close()
	out_sock.close()







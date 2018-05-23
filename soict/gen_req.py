import sys, os, time
import socket

with open('accesslog_test', 'r') as fin:
	for line in fin:
		if len(line.rstrip()) == 0:
			exit()
		request = line.split('"')[1].rstrip() + "\r\nHost: localhost\r\n\r\n"
		print request
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(('localhost', 80))
		s.sendall(request)
		data = s.recv(1024)
		print data
		s.close()


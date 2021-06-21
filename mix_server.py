import socket

class mix_server:

	BUFFER_SIZE = 1024

	def start(self, ip, port):
		self.__socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.bind((ip, port))

		while True:
			data = sock.recv(BUFFER_SIZE)
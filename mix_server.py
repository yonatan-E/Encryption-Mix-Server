import socket
import sys
import time
import threading
import random

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class mix_server:

	BUFFER_SIZE = 1024
	MESSAGE_SENDING_INTERVAL = 1

	def __init__(self, private_key):
		self.__private_key = private_key
		self.__messages_queue = []

	def start(self, ip, port):
		self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.__sock.bind((ip, port))

		self.__sender_thread = threading.Timer(self.MESSAGE_SENDING_INTERVAL, self.__send_messages)
		self.__sender_thread.start()

	def stop(self):
		self.__sock.close()
		self.__sender_thread.cancel()

	def recieve_message(self):
		data = self.__sock.recv(self.BUFFER_SIZE)

		plaintext = self.__private_key.decrypt(
			data,
			padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None
			)
		)

		self.__messages_queue.append({
			'address': (socket.inet_ntoa(plaintext[0:4]), plaintext[4:6].from_bytes(2, 'big')),
			'content': plaintext[6:]
		})

	def __send_messages(self):
		while True:
			time.sleep(self.MESSAGE_SENDING_INTERVAL)

			random.shuffle(self.__messages_queue)
			for message in self.__messages_queue:
				self.__sock.sendto(message['content'], message['address'])

			self.__messages_queue = []

if __name__ == '__main__':
	if len(sys.argv) < 3:
		exit(1)

	with open(f'sk{int(sys.argv[1])}.pem', 'rb') as pem:
	    pemlines = pem.read()
	private_key = load_pem_private_key(pemlines, None, default_backend())

	server = mix_server(private_key)
	server.start('localhost', int(sys.argv[2]))

	while True:
		server.recieve_message()
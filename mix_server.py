import socket
import sys
import time
import threading

import struct
import random

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class mix_server:

	BUFFER_SIZE = 1024
	MESSAGE_SENDING_INTERVAL = 1

	'''
	should get the private key using:

	with open(private_key_file, 'rb') as pem:
        pemlines = pem.read()
    private_key = load_pem_private_key(pemlines, None, default_backend())
	'''

	def __init__(self, private_key):
		self.__private_key = private_key
		self.__messages_queue = []

	def start(self):
		self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.__sock.bind((ip, port))

		self.__sender_thread = threading.Timer(MESSAGE_SENDING_INTERVAL, self.__send_messages)
		self.__sender_thread.start()

	def recieve_message(self, ip, port):
		data = sock.recv(BUFFER_SIZE)

		plaintext = self.__private_key.decrypt(
			data,
			padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None
			)
		)

		self.__messages_queue.append({
			'address': (socket.inet_ntoa(plaintext[0:4]), struct.unpack('H', plaintext[4:6])),
			'content': plaintext[6:]
		})

	def __send_messages(self):
		while True:
			time.sleep(MESSAGE_SENDING_INTERVAL)

			random.shuffle(self.__messages_queue)
			for message in self.__messages_queue:
				self.__sock.sendto(message['content'], message['address'])

			self.__messages_queue = []

if __name__ == '__main__':
	if len(sys.argv) < 2:
		exit(1)

	# need to figure out if the server should create key files
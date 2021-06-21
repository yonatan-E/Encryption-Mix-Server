import socket
import time
import sys

import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class consumer_client:

	BUFFER_SIZE = 1024

	def __init__(self, key):
		self.__key = key

	def start(self, ip, port):
		self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.__sock.bind((ip, port))

	def stop(self):
		self.__sock.close()

	def recieve_message(self):
		data = sock.recv(BUFFER_SIZE)

		return Fernet(self.__key).decrypt(data)

if __name__ == '__main__':
	if len(sys.argv) < 3:
		exit(1)

	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=sys.argv[2],
		iterations=100000
	)
	key = base64.urlsafe_b64encode(kdf.derive(sys.argv[1]))

	client = reciever_client(key)
	client.start('localhost', 8000)
	
	while True:
		message = client.recieve_message()

		print(f'{message} {time.strftime('%H:%M:%S')}')

	# client.stop() somewhere
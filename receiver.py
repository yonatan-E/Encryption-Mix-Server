# ilan prais, 329034557, yonatan ehrenreich, 213192875
import socket
import time
import sys

import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class consumer_client:

	BUFFER_SIZE = 8192

	def __init__(self, key):
		self.__key = key

	def start(self, ip, port):
		# opening a socket and binding it
		self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.__sock.bind((ip, port))

	def stop(self):
		self.__sock.close()

	def recieve_message(self):
		data = self.__sock.recv(self.BUFFER_SIZE)

		# decrypting the recieved message
		return Fernet(self.__key).decrypt(data)

if __name__ == '__main__':
	if len(sys.argv) < 4:
		exit(1)

	# creating a symetric key from the password and the salt
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=sys.argv[2].encode(),
		iterations=100000,
		backend=default_backend()
	)
	key = base64.urlsafe_b64encode(kdf.derive(sys.argv[1].encode()))

	# starting the client and recieving all of the messages
	client = consumer_client(key)
	client.start('localhost', int(sys.argv[3]))
	
	while True:
		message = client.recieve_message()

		print(f'{message.decode()} {time.strftime("%H:%M:%S")}')

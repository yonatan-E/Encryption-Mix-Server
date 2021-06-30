# ilan prais, 329034557, yonatan ehrenreich, 213192875
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

	BUFFER_SIZE = 4096
	MESSAGE_SENDING_INTERVAL = 1

	def __init__(self, private_key):
		self.__private_key = private_key
		self.__messages_queue = []

		self.__sending_thread_running = False

	def start(self, ip, port):
		# opening a socket and binding it
		self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.__sock.bind((ip, port))

		# starting a thread to run in background and clear the messages queue every time interval
		self.__sending_thread_running = True
		self.__sender_thread = threading.Thread(target=self.__send_messages)
		self.__sender_thread.start()

		# this mutex will prevent race conditions on the messages queue
		self.__lock = threading.Lock()

	def stop(self):
		# closing the socket and stopping the thread
		self.__sock.close()
		self.__sending_thread_running = False

	def recieve_message(self):
		data, address = self.__sock.recvfrom(self.BUFFER_SIZE)

		# decrypting the recieved message with the server's private key
		return self.__private_key.decrypt(
			data,
			padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None
			)
		)

	def append_to_queue(self, message, address):
		# locking the mutex
		self.__lock.acquire()
		# appending the message to the sending queue
		self.__messages_queue.append({
			'address': address,
			'content': message
		})
		# releasing the mutex
		self.__lock.release()

	def __send_messages(self):
		while self.__sending_thread_running:
			if len(self.__messages_queue) > 0:
				# locking the mutex
				self.__lock.acquire()
				# shuffeling the pending messages queue
				random.shuffle(self.__messages_queue)
				# sending all of the pending messages in the sending queue
				for message in self.__messages_queue:
					self.__sock.sendto(message['content'], message['address'])

				self.__messages_queue = []
				# releasing the mutex
				self.__lock.release()

			time.sleep(self.MESSAGE_SENDING_INTERVAL)

if __name__ == '__main__':
	if len(sys.argv) < 3:
		exit(1)

	# loading the server's private key from a file
	with open(f'sk{int(sys.argv[1])}.pem', 'rb') as pem:
	    pemlines = pem.read()
	private_key = load_pem_private_key(pemlines, None, default_backend())

	# starting the server
	server = mix_server(private_key)
	server.start('localhost', int(sys.argv[2]))

	while True:
		message = server.recieve_message()
		server.append_to_queue(message[6:], (socket.inet_ntoa(message[0:4]), int.from_bytes(message[4:6], 'big')))
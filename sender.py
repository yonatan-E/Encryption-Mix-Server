# ilan prais, 329034557, yonatan ehrenreich, 213192875
import socket
import time
import sys
import threading

import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SERVERS_FILE = 'ips.txt'

class producer_client:

	MESSAGE_SENDING_INTERVAL = 1

	def __init__(self):
		self.__messages_queue = []

		self.__sending_thread_running = False

	def start(self):
		# opening a socket
		self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

		# this thread will run in background and send the messages which their round count has reached to 0, every time interval
		self.__sending_thread_running = True
		self.__sender_thread = threading.Thread(target=self.__send_messages)
		self.__sender_thread.start()

		# this mutex will prevent race conditions on the messages queue
		self.__lock = threading.Lock()

	def stop(self):
		# closing the socket and stopping the thread
		self.__sock.close()
		self.__sending_thread_running = False

	def append_to_message_queue(self, message_json): # message should be in format {content, servers (list of tuples (IP, PORT)), round, key, dest-addr (IP, PORT)}
		# encrypting the plaintext with the symetric key
		ciphertext = Fernet(message_json['key']).encrypt(message_json['content'].encode())

		# iterating over all of the servers and encrypting the ciphertext with the public keys of the servers, in reverse order
		# for every server encrypting (ip || port || ciphertext) with the server's public key, when the ip and the port are the ip and the port are the
		# destination of the server
		servers = message_json['servers']
		for i in reversed(range(0, len(servers))):
			if i < len(servers) - 1:
				address = servers[i + 1]['address']
			else:
				# the destination of the last server is dest-addr
				address = message_json['dest-addr']

			ciphertext = servers[i]['public-key'].encrypt(
				socket.inet_aton(address[0]) + address[1].to_bytes(2, 'big') + ciphertext,
				padding.OAEP(
					mgf=padding.MGF1(algorithm=hashes.SHA256()),
					algorithm=hashes.SHA256(),
					label=None
				)
			)

		# locking the mutex
		self.__lock.acquire()
		# appending the message to the pending messages queue
		self.__messages_queue.append({
			'content': ciphertext,
			'address': servers[0]['address'],
			'remaining-rounds': message_json['round']
		})
		# releasing the mutex
		self.__lock.release()

		return ciphertext

	def flush_messages_queue(self):
		while len(self.__messages_queue) > 0:
			time.sleep(self.MESSAGE_SENDING_INTERVAL)

	def __send_messages(self):
		while self.__sending_thread_running:
			if len(self.__messages_queue) > 0:
				new_messages_queue = []

				# locking the mutex
				self.__lock.acquire()
				# sending all of the pending messages which their remaining rounds count is 0
				for message in self.__messages_queue:

					if message['remaining-rounds'] == 0:
						self.__sock.sendto(message['content'], message['address'])
					else:
						message['remaining-rounds'] -= 1
						new_messages_queue.append(message)

				self.__messages_queue = new_messages_queue
				# releasing the mutex
				self.__lock.release()

			time.sleep(self.MESSAGE_SENDING_INTERVAL)

def generate_message_json(line, servers): # servers is a list of tuples (IP, PORT)
	message = {}

	props = line.split(' ')

	# initializing the content of the message
	message['content'] = props[0]

	# initializing the list of servers. the list contains elements of the form {address: (ip, port), public-key: public-key}
	message['servers'] = []
	for index in props[1].split(','):
		with open(f'pk{index}.pem', 'rb') as pem:
		    pemlines = pem.read()
		public_key = load_pem_public_key(pemlines, default_backend())

		message['servers'].append({'address': servers[int(index) - 1], 'public-key': public_key})

	message['round'] = int(props[2])

	# creating a symetric key from the password and the salt
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=props[4].encode(),
		iterations=100000,
		backend=default_backend()
	)
	message['key'] = base64.urlsafe_b64encode(kdf.derive(props[3].encode())) 

	# initializing the destination address
	message['dest-addr'] = (props[5], int(props[6]))

	return message

if __name__ == '__main__':
	if len(sys.argv) < 2:
		exit(1)

	# reading the servers from the servers file
	servers = []

	with open(SERVERS_FILE, 'r+') as servers_file:
		for line in servers_file:
			props = line.split(' ')
			servers.append((props[0], int(props[1])))

	# reading all of the messages from the messages file
	with open(f'messages{sys.argv[1]}.txt', 'r+') as messages_file:
		messages = [line for line in messages_file]

	# starting the client and sending all of the messages
	client = producer_client()
	client.start()
	
	for message in messages:
		client.append_to_message_queue(generate_message_json(message, servers))

	client.flush_messages_queue()
	client.stop()
		
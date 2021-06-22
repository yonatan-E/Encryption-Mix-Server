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

	def start(self):
		self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

		self.__sender_thread = threading.Timer(self.MESSAGE_SENDING_INTERVAL, self.__send_messages)
		self.__sender_thread.start()

	def stop(self):
		self.__sock.close()
		self.__sender_thread.cancel()

	def send_message(self, message_json): # message should be in format {content, servers (list of tuples (IP, PORT)), round, key, dest-addr (IP, PORT)}
		ciphertext = Fernet(message_json['key']).encrypt(message_json['content'].encode())

		servers = message_json['servers']
		for i in reversed(range(0, len(servers))):
			if i < len(servers) - 1:
				address = servers[i + 1]['address']
			else:
				address = message_json['dest-addr']

			ciphertext = servers[i]['public-key'].encrypt(
				socket.inet_aton(servers[i]['address'][0]) + servers[i]['address'][1].to_bytes(2, 'big') + ciphertext,
				padding.OAEP(
					mgf=padding.MGF1(algorithm=hashes.SHA256()),
					algorithm=hashes.SHA256(),
					label=None
				)
			)

		self.__messages_queue.append({
			'content': ciphertext,
			'address': servers[0]['address'],
			'remaining-rounds': message_json['round']
		})

		return ciphertext

	def __send_messages(self):
		while True:
			time.sleep(self.MESSAGE_SENDING_INTERVAL)

			new_messages_queue = []

			for message in self.__messages_queue:
				message['remaining-rounds'] -= 1

				if message['remaining-rounds'] == 0:
					self.__sock.sendto(message['content'], message['address'])
				else:
					new_messages_queue.append(message)

			self.__messages_queue = new_messages_queue


def generate_message_json(line, servers): # servers is a list of tuples (IP, PORT)
	message = {}

	props = line.split(' ')

	message['content'] = props[0]

	message['servers'] = []
	for index in props[1].split(','):
		with open(f'pk{index}.pem', 'rb') as pem:
		    pemlines = pem.read()
		public_key = load_pem_public_key(pemlines, default_backend())

		message['servers'].append({'address': servers[int(index) - 1], 'public-key': public_key})

	message['round'] = int(props[2])

	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=props[4].encode(),
		iterations=100000,
		backend=default_backend()
	)
	message['key'] = base64.urlsafe_b64encode(kdf.derive(props[3].encode())) 

	message['dest-addr'] = (props[5], props[6])

	return message

if __name__ == '__main__':
	if len(sys.argv) < 2:
		exit(1)

	servers = []

	with open(SERVERS_FILE, 'r+') as servers_file:
		for line in servers_file:
			props = line.split(' ')
			servers.append((props[0], int(props[1])))

	with open(f'messages{sys.argv[1]}.txt', 'r+') as messages_file:
		messages = [line for line in messages_file]

	client = producer_client()
	client.start()
	
	for message in messages:
		client.send_message(generate_message_json(message, servers))

	client.stop()
import socket
import time
import sys
import threading

import struct

import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class producer_client:

	def __init__(self):
		self.__messages_queue = []

	def start(self):
		self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

		self.__sender_thread = threading.Timer(MESSAGE_SENDING_INTERVAL, self.__send_messages)
		self.__sender_thread.start()

	def stop(self):
		self.__sock.close()
		self.__sender_thread.cancel()

	def send_message(self, message_json): # message should be in format {content, servers (list of tuples (IP, PORT)), round, key, dest-addr (IP, PORT)}
		ciphertext = Fernet(message_json['key']).encrypt(message_json['content'].encode())

		for i in reversed(range(0, len(message_json['servers']))):
			if i < len(message_json['servers']) - 1:
				address = message_json['servers'][i + 1]['address']
			else:
				address = message_json['dest-addr']

			ciphertext = server['public_key'].encrypt(
				socket.inet_aton(server['address'][0]) + struct.pack('H', server['address'][1]) + ciphertext,
				padding.OAEP(
					mgf=padding.MGF1(algorithm=hashes.SHA256()),
					algorithm=hashes.SHA256(),
					label=None
				)
			)

		self.__messages_queue.append({
			'content': ciphertext,
			'address': message_json['servers'][0]['address'],
			'remaining-rounds': message_json['round']
		})

		return ciphertext

	def __send_messages(self):
		while True:
			time.sleep(MESSAGE_SENDING_INTERVAL)

			new_messages_queue = []

			for message in self.__messages_queue:
				message['remaining-rounds'] -= 1

				if message['remaining-rounds'] == 0:
					self.__sock.sendto(message['content'], message['address'])
				else:
					new_messages_queue.append(message)

			self.__messages_queue = new_messages_queue


def generate_message_json(self, line, servers): # servers is a list of tuples (IP, PORT)
	message = {}

	props = message.split(' ')

	message['content'] = props[0]

	message['servers'] = []
	for index in props[1].split(','):
		with open(f'pk{index}.pem', 'rb') as pem:
		    pemlines = pem.read()
		public_key = load_pem_public_key(pemlines, default_backend())

		message['servers'].append({'address': servers[int(index) - 1], 'public-key': public_key})

	message['round'] = props[2]

	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=props[4],
		iterations=100000
	)
	message['key'] = base64.urlsafe_b64encode(kdf.derive(props[3])) 
	
	message['dest-addr'] = (props[5], props[6])

if __name__ == '__main__':
	if len(sys.argv) < 2:
		exit(1)

	with open(sys.argv[1], 'r+') as messages_file:
		messages = messages_file.read().split('\n')

	client = producer_client()
	client.start()

	for message in messages:
		client.send_message(generate_message_json(message))

	client.stop()

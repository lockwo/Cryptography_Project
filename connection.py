import socket
import time

class Connection:
	def __init__(self, client=True, host='localhost', port=3000):
		if client:
			try:
				self.socket = self.__create_client_socket(host, port)
				print(f'client started at {host}:{port}')
			except socket.error as err:
				raise ConnectionRefusedError("could not connect")

		else:
			try:
				self.socket = self.__create_server_socket(host, port)
				print(f'server started at {host}:{port}')
			except socket.error as err:
				raise ConnectionRefusedError("could not connect")

	@staticmethod
	def __create_server_socket(host, port):
		socket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		socket_server.bind((host, port))
		socket_server.listen(1)
		server_socket, addr = socket_server.accept()
		socket_server.close()
		return server_socket

	@staticmethod
	def __create_client_socket(host, port):
		client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client_socket.connect((host, port))

		return client_socket

	def send_message(self, message):
		self.socket.send(message.encode())
	
	def receive_message(self):
		return self.socket.recv(2048).decode()

import select
import socket
import sys
import signal
import math

from utils.messages import *
from utils.digital_signature import DigitalSignature
from utils.symmetric_encryption import SymmetricEncryption
from utils.keys import DIFFIE_HELLMAN_PUBLIC_G
from utils.keys import DIFFIE_HELLMAN_PUBLIC_N
from utils.keys import GET_DIFFIE_HELLMAN_SECRET
from utils.keys import SERVER_SIGNING_PRIVATE_KEY
from utils.numbers import to_int
from utils.BankAccounts import BankAccounts

DIFFIE_HELLMAN_SECRET_RANDOM_SERVER = GET_DIFFIE_HELLMAN_SECRET()
MAX_MESSAGE_SIZE = 500

def format_peername(sock):
	peername = sock.getpeername()
	return f'{peername[0]}:{peername[1]}'

class Server:
	def __init__(self):
		self.bank_accounts = BankAccounts()

	def connect(self, port=3000, max_connections=5):
		try:
			self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.server_socket.bind(('', port))
			self.server_socket.listen(3)

		except socket.error as err:
			raise ConnectionError(f'could not connect to port {port}')
  
		self.session_keys = {}
		self.message_numbers = {}

		self.select_args = ([], [], [])
		self.max_connections = max_connections
		signal.signal(signal.SIGINT, self.close_all_connections)
	
	def start(self):
		sockets_in, _, sockets_err = self.select_args
		sockets_in.extend([self.server_socket])

		while True:
			sockets_in_ready, _, sockets_err_ready = select.select(*self.select_args)

			for sock in sockets_in_ready:
				if sock is sockets_in[0]:
					connection, client_address = sock.accept()

					if len(sockets_in) > self.max_connections + 2:
						connection.send(ERR_TOO_MANY_CONNS)
						self.close_socket(connection)
					else:
						success = self.initialize_connection(connection)
						if success:
							connection.setblocking(0)
							sockets_in.append(connection)
						else:
							self.close_socket(connection)
				else:
					keep_alive = self.handle_message(sock)
					if not keep_alive:
						self.close_socket(sock)
						if sock in sockets_in: sockets_in.remove(sock)

			for sock in sockets_err_ready:
				print(f'{format_peername(sock)}: encountered an error')
				self.close_socket(sock)

	def close_socket(self, sock):
		if sock in self.select_args[0]:
			self.select_args[0].remove(sock)
		if sock in self.session_keys:
			self.session_keys.pop(sock)
 
		try:
			print(f'{format_peername(sock)}: closed')
			sock.close()
		except:
			pass

	def close_all_connections(self, signal=None, frame=None):
		for sock in self.select_args[0][1:]:
			self.close_socket(sock)
		sys.exit(0)


	def send_message(self, sock, message, encrypted=True, message_no=None):
		if message_no != None:
			assert('|' not in message)
			message = f'{message_no}|{message}'
		
		message += '|' + DigitalSignature.sign(message, SERVER_SIGNING_PRIVATE_KEY)

		if encrypted:
			assert(sock in self.session_keys)
			message = SymmetricEncryption.encrypt(message, self.session_keys[sock])

		sock.send(message.encode())

	def receive_message(self, sock, encrypted=True, buffer_size=MAX_MESSAGE_SIZE):
		message = sock.recv(buffer_size).decode()
		if message == '':
			return False, ''

		if len(message) == buffer_size:
			print('NOTE: potential overflow. consider increasing message buffer size')

		if encrypted:
			assert(sock in self.session_keys)
			message, verified = SymmetricEncryption.decrypt(message, self.session_keys[sock])
			if not verified:
				return 'MAC does not match!', None

		return False, message

	def initialize_connection(self, sock):
		self.send_message(sock, OK_START_KEY_EXCHANGE, encrypted=False)

		error, dh_step_1_raw = self.receive_message(sock, encrypted=False, buffer_size=1500)
		if error: return False

		dh_step_1 = extract_diffie_hellman_message(dh_step_1_raw)
		# print(f'recieved: ({len(str(dh_step_1))}) {str(dh_step_1)[:10]}...{str(dh_step_1)[-10:]}')
		if dh_step_1 == None:
			self.send_message(sock, ERR_KEY_EXCHANGE_FAILURE, encrypted=False)
			print(f'{format_peername(sock)}: key exchange failed')
			return False

		dh_step_2 = pow(DIFFIE_HELLMAN_PUBLIC_G, DIFFIE_HELLMAN_SECRET_RANDOM_SERVER, DIFFIE_HELLMAN_PUBLIC_N)
		self.send_message(sock, format_diffie_hellman_message(dh_step_2), encrypted=False)
		# print(f'sending: ({len(str(dh_step_2))}) {str(dh_step_2)[:10]}...{str(dh_step_2)[-10:]}')	
		self.session_keys[sock] = pow(dh_step_1, DIFFIE_HELLMAN_SECRET_RANDOM_SERVER, DIFFIE_HELLMAN_PUBLIC_N)

		# print(f'{format_peername(sock)}: generated shared key: [{str(self.session_keys[sock])[0:5]}...]')

		error, session_start_req = self.receive_message(sock, encrypted=True)

		if error or session_start_req != OK_START_SESSION_REQ:
			print(f'{format_peername(sock)}: key exchange confirmation failed')
			self.send_message(sock, ERR_KEY_EXCHANGE_CONFIRMATION_FAILED, encrypted=False)
			return False

		self.send_message(sock, OK_START_SESSION_RES, encrypted=True)
		self.message_numbers[sock] = 0
		print(f'{format_peername(sock)}: key exchange completed. starting session')
		return True

	def handle_input(self):
		line = sys.stdin.readline().strip()
		if line == '':
			self.close_all_connections()
			print('>  ')
		elif line == 'show-accounts':
			print('>  showing acconuts')
		elif line == 'show-connected':
			print('>  show connected')
		elif line == 'quit':
			print('>  goodbye')
			self.close_all_connections()
		elif line == 'help':
			print('>  show help')
		else:
			print('>  unknown command')


	def handle_message(self, sock):
		key = self.session_keys[sock]
		error, message = self.receive_message(sock, encrypted=True)
		if message == '':
			return False
		if error:
			print(f'{format_peername(sock)}: {error}')
			return False

		command, account, message_no, args = extract_general_message(message)

		if message_no != self.message_numbers[sock]:
			print(f'{format_peername(sock)}: error unexpected message number (got {message_no} but was expecting {self.message_numbers[sock]})')
			self.send_message(sock, 'unexpected message number', message_no=self.message_numbers[sock] + 1)
			return False

		if not command or command not in ['echo', 'show-balance', 'withdraw', 'deposit']:
			print(f'{format_peername(sock)}: error unknown command', message_no=self.message_numbers[sock] + 1)
			return False

		if not self.bank_accounts.areValidCredentials(*account):
			print(f'{format_peername(sock)}: error invalid credentials')
			self.send_message(sock, 'invalid username or password', message_no=self.message_numbers[sock] + 1)
			self.message_numbers[sock] += 2
			return True

		response_message = None
		if command == 'echo':
			response_message = f'you are logged in as {account[0]}'
		elif command == 'show-balance':
			balance = self.bank_accounts.getBalance(account[0])
			response_message = f'balance: ${balance:.2f}'
		elif command == 'withdraw':
			if len(args) != 2:
				print(f'{format_peername(sock)}: error invalid format')
				self.send_message(sock, 'invalid format', message_no=self.message_numbers[sock] + 1)
				return False
			dollars = to_int(args[0])
			cents = to_int(args[1])

			if dollars == None or cents == None:
				print(f'{format_peername(sock)}: error invalid format')
				self.send_message(sock, 'invalid format', message_no=self.message_numbers[sock] + 1)
				return False

			success = self.bank_accounts.withdraw(account[0], dollars + (cents / 100))
			response_message = 'withdraw completed' if success else 'insufficient funds'
		elif command == 'deposit':
			if len(args) != 2:
				print(f'{format_peername(sock)}: error invalid format')
				self.send_message(sock, 'invalid format', message_no=self.message_numbers[sock] + 1)
				return False

			dollars = to_int(args[0])
			cents = to_int(args[1])
			if dollars == None or cents == None:
				print(f'{format_peername(sock)}: error invalid amount')
				self.send_message(sock, 'invalid format', message_no=self.message_numbers[sock] + 1)
				return False

			self.bank_accounts.deposit(account[0], dollars + (cents / 100))
			response_message = 'deposit completed'

		self.send_message(sock, response_message, message_no=self.message_numbers[sock]+1)
		self.message_numbers[sock] += 2
		return True

if __name__ == '__main__':
	server = Server()
	server.connect()
	server.start()

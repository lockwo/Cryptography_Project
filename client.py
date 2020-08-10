import socket
import sys
import signal
import math

from utils.messages import *
from utils.symmetric_encryption import SymmetricEncryption
from utils.constants import DIFFIE_HELLMAN_PUBLIC_G
from utils.constants import DIFFIE_HELLMAN_PUBLIC_N
from utils.constants import DIFFIE_HELLMAN_SECRET_RANDOM_CLIENT
from utils.constants import SERVER_SIGNING_PUBLIC_KEY

MAX_MESSAGE_SIZE = 500

def format_peername(sock):
	peername = sock.getpeername()
	return f'{peername[0]}:{peername[1]}'

def to_float(amt_str):
	try:
		assert(not amt_str.isalpha())
		amt = float(amt_str)
		assert(amt >= 0)
		return amt

	except ValueError:
		return None
	except AssertionError:
		return None

class Client:
	def send_message(self, message, encrypted=True):
		if encrypted:
			message = SymmetricEncryption.encrypt_unsigned(message, self.session_key)

		self.socket.send(message.encode())

	def receive_message(self, encrypted=True, buffer_size=MAX_MESSAGE_SIZE):
		message = self.socket.recv(buffer_size).decode()

		if message == '':
			return False, ''

		if len(message) == buffer_size:
			print('NOTE: potential overflow. consider increasing message buffer size')

		if encrypted:
			assert(self.session_key != None)
			message, verified = SymmetricEncryption.decrypt_signed(message, self.session_key, SERVER_SIGNING_PUBLIC_KEY)
			if not verified:
				return 'Signature or MAC do not match!', None

		return False, message

	def close_connection(self, signal=None, frame=None):
		print('closed socket')
		try:
			self.socket.close()
		except:
			pass
		sys.exit(0)

	def connect(self, host='localhost', port=3000):
		self.session_key = None
		self.username = None
		self.password = None
		self.message_no = 0

		try:
			self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.socket.connect((host, port))
		except socket.error as err:
			raise ConnectionError(f'could not connect to {host}:{port}')
	
		signal.signal(signal.SIGINT, self.close_connection)
		self.initialize_connection()

	def initialize_connection(self):
		error, message = self.receive_message(encrypted=False)
		if message == '':
			raise ConnectionAbortedError(f'connection closed before handshake completed')
		if message == ERR_TOO_MANY_CONNS:
			raise ConnectionRefusedError(f'server refused connection due to high load')
		if message != OK_START_KEY_EXCHANGE:
			raise ConnectionError(f'server did not ask to start key exchange')

		dh_step_1 = pow(DIFFIE_HELLMAN_PUBLIC_G, DIFFIE_HELLMAN_SECRET_RANDOM_CLIENT, DIFFIE_HELLMAN_PUBLIC_N)
		# print(f'sending: ({len(str(dh_step_1))}) {str(dh_step_1)[:10]}...{str(dh_step_1)[-10:]}')
		self.send_message(format_diffie_hellman_message(dh_step_1), encrypted=False)

		error, dh_step_2_raw = self.receive_message(encrypted=False, buffer_size=1500)
		if error:
			print(f'error: {error}')
			raise ConnectionError(error)
		
		dh_step_2 = extract_diffie_hellman_message(dh_step_2_raw)
		# print(f'received: ({len(str(dh_step_2))}) {str(dh_step_2)[:10]}...{str(dh_step_2)[-10:]}')

		if dh_step_2 == None:
			self.send_message(ERR_KEY_EXCHANGE_FAILURE, encrypted=False)
			raise ConnectionError(f'could not perform successful key exchange')

		self.session_key = pow(dh_step_2, DIFFIE_HELLMAN_SECRET_RANDOM_CLIENT, DIFFIE_HELLMAN_PUBLIC_N)
		# print(f'generated shared key: [{str(self.session_key)[0:5]}...]')

		self.send_message(OK_START_SESSION_REQ, encrypted=True)
		error, session_start_res = self.receive_message(encrypted=True)
		if session_start_res != OK_START_SESSION_RES:
			raise ConnectionError('server did not confirm session start')

		print(f'key exchange completed. starting session')

	def start_session(self):
		local_commands = ['login', 'logout', 'quit', 'help', '']
		logged_in_commands = ['echo', 'show-balance', 'withdraw', 'deposit']

		while True:
			prompt = None
			if self.username:
				prompt = f'{self.username}@{format_peername(self.socket)}: ' 
			else:
				prompt = f'public@{format_peername(self.socket)}: '

			line = input(prompt).strip()
			message_to_send = None

			if not line in local_commands and not line in logged_in_commands:
				print('>  unknown command')
				continue

			if not line or line == 'quit':
				print('>  goodbye')
				self.close_connection()
				return

			if line == 'help':
				print('''
>  available while logged out:
>    login
>    logout
>    quit
>    help
>  ------------------------------------
>  available when logged in:
>    echo
>    show-balance
>    withdraw
>    deposit
				'''.strip())
				continue

			if line == 'login':
				username = input('username: ').strip()
				if not username:
					print('canceled')
					continue
				password = input('password: ').strip()
				if not password:
					print('canceled')
					continue

				self.username = username
				self.password = password
				print(f'>  logged in as {self.username}\n>  note that credentials will not be checked until you make a transaction')
				continue

			if line == 'logout':
				self.username = None
				self.password = None
				continue

			if not self.username or not self.password:
				print('please login first')
				continue

			if line in logged_in_commands[:-2]:
				message_to_send = format_general_message(line, self.username, self.password, self.message_no)

			if line in logged_in_commands[-2:]:
				amount_str = input('amount: $').strip()
				amount = to_float(amount_str)
				if amount == None:
					print('invalid amount')
					continue
	
				cents, dollars = math.modf(amount)
				cents = int(round(cents * 100))
				dollars = int(dollars)

				message_to_send = format_general_message(line, self.username, self.password, self.message_no, dollars, cents)

			self.send_message(message_to_send)
			self.message_no += 1

			error, res = self.receive_message()
			if error:
				print(f'error: {error}')
				self.close_connection()
				return
			if res == '':
				print(f'connection closed')
				return

			print(f'>  {res}')

if __name__ == '__main__':
	c = Client()
	c.connect()
	c.start_session()
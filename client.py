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
from utils.keys import SERVER_SIGNING_PUBLIC_KEY
from utils.numbers import to_int, to_float

DIFFIE_HELLMAN_SECRET_RANDOM_CLIENT=GET_DIFFIE_HELLMAN_SECRET()
MAX_MESSAGE_SIZE = 1000
SERVER_SIGNING_PUBLIC_KEY = [0, 0, 0, 0]
def format_peername(sock):
	peername = sock.getpeername()
	return f'{peername[0]}:{peername[1]}'

class Client:
	
	def send_message(self, message, encrypted=True):
		if encrypted:
			message = SymmetricEncryption.encrypt(message, self.session_key)

		self.socket.send(message.encode())

	def receive_message(self, encrypted=True, buffer_size=MAX_MESSAGE_SIZE, first=False, k=None):
		if first:
			buffer_size = 5000
		message = self.socket.recv(buffer_size).decode()
		
		if message == '':
			return False, ''
		if len(message) == buffer_size:
			print('NOTE: potential overflow. consider increasing message buffer size')

		if encrypted:
			assert(self.session_key != None)

			message, verified = SymmetricEncryption.decrypt(message, self.session_key)
			if not verified:
				return 'MAC do not match!', None
		
		signature_deliminator = message.rfind('|')
		if signature_deliminator == -1:
			return 'message is not signed', None


		signature = message[signature_deliminator+1:]
		message = message[:signature_deliminator]

		if not DigitalSignature.verify(message, signature, SERVER_SIGNING_PUBLIC_KEY):
			return 'message signature does not match that of the server', None

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
		if error:
			raise ConnectionError(error)
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
		#print(f'generated shared key: [{str(self.session_key)[0:5]}...]')

		self.send_message(OK_START_SESSION_REQ, encrypted=True)
		error, session_start_res = self.receive_message(encrypted=True, first=True, k=SERVER_SIGNING_PUBLIC_KEY)
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
				line = 'echo'
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

			error, res = self.receive_message()
			if error:
				print(f'error: {error}')
				self.close_connection()
				return
			if res == '':
				print(f'remote connection closed')
				self.close_connection()
				return
			
			message_no_deliminator = res.find('|')
			if message_no_deliminator == -1:
				print('invalid format')
				self.close_connection()
				return

			received_message_no = to_int(res[:message_no_deliminator])
			if received_message_no != self.message_no + 1:
				print('unexpected message number')
				self.close_connection()
				return

			res = res[message_no_deliminator+1:]
			if res == 'invalid username or password':	
				self.password = None	
				self.username = None	
			self.message_no+=2
			print(f'>  {res}')

if __name__ == '__main__':
	c = Client()
	c.connect()
	c.start_session()

ERR_TOO_MANY_CONNS = 'ERR|too many active connections. please try again later'
OK_START_KEY_EXCHANGE = 'OK|start key exchange'
ERR_KEY_EXCHANGE_FAILURE = 'ERR|key exchange failure'
OK_START_SESSION_REQ = 'OK|request to start session'
OK_START_SESSION_RES = 'OK|yes please start session'
ERR_KEY_EXCHANGE_CONFIRMATION_FAILED = 'ERR|key exchange confirmation failed'

def format_diffie_hellman_message(num):
	return f'OK|DH1.{num}'

def extract_diffie_hellman_message(message):
	if not message.startswith('OK|DH1.') or not message[7:].isdigit():
		return None
	return int(message[7:])

def format_general_message(type, username, password, message_no, *args):
	for arg in args:
		assert('.' not in str(arg))
	args = (str(arg) for arg in args)

	m = None
	if args:
		m = f'OK|{username}.{password}|{message_no}|{type}.' + '.'.join(args)
	else:
		m = f'OK|{username}.{password}|{message_no}|{type}'
	return m

INVALID_MESSAGE_RESPONSE = (None, None, None, None)

def extract_general_message(message):
	if not message.startswith('OK|'):
		return INVALID_MESSAGE_RESPONSE
	message = message[3:]

	credentials_end = message.find('|')
	if credentials_end < 0:
		return INVALID_MESSAGE_RESPONSE

	credentials = message[:credentials_end].split('.')
	if len(credentials) != 2:
		return INVALID_MESSAGE_RESPONSE
	message = message[credentials_end + 1:]


	message_no_end = message.find('|')
	if message_no_end < 0:
		return INVALID_MESSAGE_RESPONSE
	message_no_raw = message[:message_no_end]
	if message_no_raw.isalpha() or not message_no_raw.isdigit():
		return INVALID_MESSAGE_RESPONSE
	try:
		message_no = int(message_no_raw)
	except:
		return INVALID_MESSAGE_RESPONSE
	message = message[message_no_end + 1:]

	split_message = message.split('.')
	return split_message[0], tuple(credentials), message_no, split_message[1:]

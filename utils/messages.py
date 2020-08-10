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

def format_general_message(type, username, password, *args):
	for arg in args:
		assert('.' not in str(arg))
	args = (str(arg) for arg in args)

	m = None
	if args:
		m = f'OK|{username}.{password}|{type}.' + '.'.join(args)
	else:
		m = f'OK|{username}.{password}|{type}'
	return m

def extract_general_message(message):
	if not message.startswith('OK|'):
		return None, None, None
	message = message[3:]

	credentials_end = message.find('|')
	if credentials_end < 0:
		return None, None, None

	credentials = message[:credentials_end].split('.')
	if len(credentials) != 2:
    		return None, None, None
	message = message[credentials_end + 1:]

	split_message = message.split('.')
	return split_message[0], credentials, split_message[1:]
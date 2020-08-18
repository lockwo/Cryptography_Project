from crypto.AES import AES256_encrypt, AES256_decrypt
from crypto.SHA1 import SHA1

def truncate_key(key):
	key = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF & key
	return key

class SymmetricEncryption:
	@staticmethod
	def encrypt(raw_message, aes_key):
		aes_key = truncate_key(aes_key)

		message_hash = SHA1(raw_message)
		message = raw_message + '|' + message_hash

		return ':'.join([ str(x) for x in AES256_encrypt(message, aes_key)])

	@staticmethod
	def decrypt(message, aes_key):
		if message.startswith('ERR|'):
			return None, False

		aes_key = truncate_key(aes_key)
		message = [int(x) for x in message.split(':')]
		decrypted = AES256_decrypt(message, aes_key).strip()

		hash_deliminator = decrypted.rfind('|')
		if hash_deliminator == -1:
			return None, False

		message_body = decrypted[:hash_deliminator]
		message_hash = decrypted[ hash_deliminator + 1:]
		if SHA1(message_body) != message_hash:
			return None, False

		return message_body, True

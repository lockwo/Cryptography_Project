from crypto.AES import AES256_encrypt, AES256_decrypt
from crypto.SHA1 import SHA1
from crypto.sig import Digital_Signature, check_sign

max_key = 2 ** 256

def truncated_key(key):
	key = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF & key
	return key

class SymmetricEncryption:
	@staticmethod
	def encrypt_signed(raw_message, aes_key, signing_key, first=False):
		aes_key = truncated_key(aes_key)
		signature = signing_key.sign(raw_message)
		message_hash = SHA1(raw_message)
		if not first:
			signature = signature[:2]
		#signature = [0]
		sign = ','.join([str(i) for i in signature])
		message = raw_message + '|' + message_hash + '|' + sign
		

		return ':'.join([ str(x) for x in AES256_encrypt(message, aes_key)])

	@staticmethod
	def decrypt_signed(message, aes_key, signing_key, first=False, k=None):
		
		if message.startswith('ERR|'):
			return None, False

		aes_key = truncated_key(aes_key)
		message = [int(x) for x in message.split(':')]
		decrypted = AES256_decrypt(message, aes_key).strip()

		sign_deliminator = decrypted.rfind('|')
		hash_deliminator = decrypted.rfind('|', 0, sign_deliminator)
		if hash_deliminator == -1:
			return None, False
		
		message_body = decrypted[:hash_deliminator]
		message_hash = decrypted[ hash_deliminator + 1:sign_deliminator]
		if SHA1(message_body) != message_hash:
			return None, False
		#print(decrypted)
		sign = [int(i) for i in decrypted[sign_deliminator+1:].split(',')]
		if first:
			k[0] = sign[2]
			k[1] = sign[3]
			k[2] = sign[4]
			k[3] = sign[5]
		else:
			sign += signing_key
		#print(k, signing_key)
		#k += signing_key
		if check_sign(sign, message_body, SHA1) is False:
			return None, False

		return message_body, True

	@staticmethod
	def encrypt_unsigned(raw_message, aes_key):
		aes_key = truncated_key(aes_key)

		message_hash = SHA1(raw_message)
		message = raw_message + '|' + message_hash

		return ':'.join([ str(x) for x in AES256_encrypt(message, aes_key)])

	@staticmethod
	def decrypt_unsigned(message, aes_key):
		if message.startswith('ERR|'):
			return None, False

		aes_key = truncated_key(aes_key)
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

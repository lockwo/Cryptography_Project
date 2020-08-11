from crypto.DSA import check_sign, modinv
import secrets 
from crypto.SHA1 import SHA1

class DigitalSignature:
	@staticmethod
	def sign(raw_message, private_key):
		# Key = p, q, g, y
		p = private_key[0]
		q = private_key[1]
		g = private_key[2]
		y = private_key[3]
		x = private_key[4]
		k = secrets.randbelow(q-1)
		r = pow(g, k, p) % q
		s = (modinv(k, q) * (int(SHA1(raw_message), 16) + x * r)) % q
		#print(r,s)
		return str(r) + "," + str(s)

	@staticmethod
	def verify(message, signature, public_key):
		# Key = r, s, p, q, g, y 
		signature = [int(i) for i in signature.split(',')]
		return check_sign(signature + public_key, message)





class DigitalSignature:
	@staticmethod
	def sign(raw_message, private_key):
		return 'some_signature_goes_here'

	@staticmethod
	def verify(message, signature, public_key):
		return signature == 'some_signature_goes_here'
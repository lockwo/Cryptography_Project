import secrets
import time
from crypto.SHA1 import SHA1
# #########################################################
# Class that mimics the functionality of a bank's database
# 
# Credential verification takes a random amount of time to
# prevent timing attacks
# 
# Also, passwords mandatorily consist of 4 random words
# https://preshing.com/20110811/xkcd-password-generator
# #########################################################

class BankAccounts:
	def __init__(self):
		self.users = {}
		for name, info in RAW_ACCOUNT_INFO.items():
			salt = f'{secrets.randbits(128):x}'
			hashed = SHA1(salt + info['password'])
			self.users[name] = {
				'balance': info['balance'],
				'salt': salt,
				'hash': hashed
			}

		print('--initialized bank accounts--')

	def areValidCredentials(self, username, password):
		time.sleep(0.1 + secrets.randbelow(5) * 0.1)
		if username not in self.users: return False

		user_salt = self.users[username]['salt']
		user_hash = self.users[username]['hash']
		return user_hash == SHA1(user_salt + password)

	def getBalance(self, username):
		assert(username in self.users)
		return self.users[username]['balance']
	
	def withdraw(self, username, amount):
		assert(username in self.users)

		if amount <= self.users[username]['balance']:
			self.users[username]['balance'] -= amount
			return True
		else:
			return False

	def deposit(self, username, amount):
		assert(username in self.users)
		self.users[username]['balance'] += amount

# #########################################################
# This data would never be stored normally, but is here
# simply so that we can load the BankAccounts.users with
# the proper information
# #########################################################
RAW_ACCOUNT_INFO = {
	"samarth": {
		"password": "woodcuriousblankpossible",
		"balance": 4.20
	},
	"owen": {
		"password": "centraltaskpureexchange",
		"balance": 10101.01
	},
	"max": {
		"password": "streetcaraboardcombination",
		"balance": 54321
	}
}
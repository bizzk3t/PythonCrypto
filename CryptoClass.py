import os
import sys
import random
from M2Crypto import EVP
from math import log
from math import ceil 
from fractions import gcd
# helper functions


def strToInt(s):
	return int(s.encode('hex'), 16)
		


# for sampling from {0,1} (flipping a single coin)

class Coin:
	def __init__(self):
		pass

	def uniform(self):
		return ord(os.urandom(1)) % 2
	
	def isMember(self, x):
		if (x == 0 or x == 1):
			return True
		return False

class Bits:
	def __init__(self, l):
		self.bitgen = Coin()
		self.size = l

	def uniform(self):
		s = [self.bitgen.uniform() for i in range(0, self.size)]
		return s

	def isMember(self, x):
		if (len(x) != self.size):
			return False
		for i in range(0, len(x)):
			if (x[i] != 0 and x[i] != 1):
				return False
		return True
			

# for set of random byte strings

class Bytes:

	def __init__(self, l):
		self.size = l

	def uniform(self):
		return os.urandom(self.size)
		
	def isMember(self, x):
		if (isinstance(x, str)):
			if (len(x)==self.size):
				return True
		return False

# for sampling from Z_n

class Zn:
	def __init__(self, n):
		self.modulus = n

	def uniform(self):
		numbytes = int(ceil(ceil(log(self.modulus)/log(2))/8.0))
		rbytes = os.urandom(numbytes)
		rint = strToInt(rbytes)
		while (rint >= self.modulus):
			rbytes = os.urandom(numbytes)
			rint = strToInt(rbytes)
		return rint


	def isMember(self, x):
		if (x >= 0 and x < n):
			return True
		return False


class Znstar:
	def __init__(self, n):
		self.modulus = n
		self.Zn = Zn(n)

	def uniform(self):
		x = self.Zn.uniform()
		while (x==0 or gcd(self.modulus,x) > 1):
			x = self.Zn.uniform()
		return x

	def isMember(self, x):
		if (x > 0 and x < self.modulus and gcd(x,self.modulus)==1):
			return True
		return False

###Utilities###

def gcd(a, b):
	return gcd(b, a%b) if b else abs(a)




###RSA###
class RSA:
	def __init__(self):
		p = self.generatePrime()
		q = self.generatePrime()
		print p
		print q
#Generate Primes
	def generatePrime(self):
		prime = random.SystemRandom().randint(0,2**128)
		if(self.primalityTest(prime)==1):
			return prime
		else:
			return self.generatePrime()

	def primalityTest(self, n):
		a = random.SystemRandom().randint(0,n-1)
		if(self.expBySquare(a, n-1)%n==1):
			return 1
		return 0

	def expBySquare(self, x, n):
		if(n == 0):
			return 1
		elif(n == 1):
			return x
		elif(n%2 == 0):	
			return self.expBySquare(x*x, n/2)
		elif(n%2 == 1):
			return self.expBySquare(x*x, (n-1)/2)


### MAC ###

class MACgame:
	def __init__(self, mac):
		self.mac = mac
		self.key = self.mac.keygen()
### Mi = message
	def mac(self, Mi):
		self.mi = Mi		
		return self.mac.Mac(self.key, Mi)		

	def ver(self, M, T):
		return self.mac.vf(self.key, M, T)

	def Finalize(self, M, T):
		return self.mac.vf(self.key, M, T) and M != self.mi




### END MAC ###


# SE INDCCA game

class IndccaSE:
	def __init__(self, SE):
		self.sescheme = SE
		self.flip = Coin()	
	

	def Initialize(self):
		self.b = self.flip.uniform()	
		self.key = self.sescheme.keygen()
		return ''

	def LR(self, M0,M1):	
		if (len(M0) != len(M1)):
			return ''
		if (self.b == 0):
			return self.sescheme.enc(self.key, M0)
		else:
			return self.sescheme.enc(self.key, M1)

	def dec(self, ctxt):	
		return self.sescheme.dec(self.key, ctxt)

	def Finalize(self, d):
		return (self.b==d)

class IndccaAdvantage:
	def __init__(self, SE, adversary):
		self.se = SE
		self.adversary = adversary

	def run(self, trials):
		adversary = self.adversary
		correct = 0
		incorrect = 0
		for i in range(0, trials):
			self.indcca = IndccaSE(self.se)
			res = self.indcca.Finalize(adversary.execute(self.indcca.Initialize(), self.indcca))
			if (res == True):
				correct = correct + 1
			else:
				incorrect = incorrect + 1

		return abs(correct/float(trials) - incorrect/float(trials))

# SE INDCPA game

class IndcpaSE:
	def __init__(self, SE):
		self.sescheme = SE
		self.flip = Coin()	
	

	def Initialize(self):
		self.b = self.flip.uniform()	
		self.key = self.sescheme.keygen()
		return ''

	def LR(self, M0,M1):	
		if (len(M0) != len(M1)):
			return ''
		if (self.b == 0):
			return self.sescheme.enc(self.key, M0)
		else:
			return self.sescheme.enc(self.key, M1)

	def Finalize(self, d):
		return (self.b==d)

class IndcpaAdvantage:
	def __init__(self, SE, adversary):
		self.se = SE
		self.adversary = adversary

	def run(self, trials):
		adversary = self.adversary
		correct = 0
		incorrect = 0
		for i in range(0, trials):
			self.indcpa = IndcpaSE(self.se)
			res = self.indcpa.Finalize(adversary.execute(self.indcpa.Initialize(), self.indcpa))
			if (res == True):
				correct = correct + 1
			else:
				incorrect = incorrect + 1

		return abs(correct/float(trials) - incorrect/float(trials))	
	

# caesar cipher class

class CaesarCipher:
	def __init__(self):
		self.keyset = Zn(26)
	
	def keygen(self):
		k = self.keyset.uniform()
		return k

	def enc(self, key, msg):
		l = len(msg)
		ctxt = [' ']*l
		for i in range(0,l):
			curr = ord(msg[i])
			if (curr >= 97 and curr <= 122):
				ctxt[i] = chr((((curr-97)+key)%26)+97)
			else:
				return ''
		return ''.join(ctxt)


	def dec(self, key, ctxt):
		return self.enc(26-key, ctxt)
# Mac 

class CBCMAC1:
	def __init__(self):
		self.keyset = Bytes(16)

	def keygen(self):
		k = self.keyset.uniform()
		return k
	
	def Mac(self, key, Mi):
		result = AES128CBC.enc(key, Mi)
		tag = result[:16]
		message = result[16:]
		return tag + message
		

	def vf(self, key, M, T):
		if(AES128CBC.dec(key, T+M) == M[16:]):
			return 1
		return 0
"""
class CBCMAC2:
	def __init__(self):
		self.keyset = Bytes(16)

	def keygen(self):
		k = self.keyset.uniform()
		return k
	
	def Mac(self, key, Mi):
		#mac the message

	def vf(self, key, M, T):
		
"""


class AES128ECB:
	def __init__(self):
		self.keyset = Bytes(16)

	def keygen(self):
		k = self.keyset.uniform()
		return k
			
	def enc(self, key, msg):
		cobj = EVP.Cipher('aes_128_ecb', key, '', 1, 0)				
		c = cobj.update(msg)
		c += cobj.final()
		return c

	def dec(self, key, ctxt):
		cblocks = ctxt[16:]
		cobj = EVP.Cipher('aes_128_ecb', key, '', 0, 0)				
		ptxt = cobj.update(cblocks)
		ptxt += cobj.final()
		return ptxt
		


class AES128CBC:
	def __init__(self):
		self.keyset = Bytes(16)
		self.ivset = Bytes(16)

	def keygen(self):
		k = self.keyset.uniform()
		return k
			
	def enc(self, key, msg):
		iv = self.ivset.uniform()
		cobj = EVP.Cipher('aes_128_cbc', key, iv, 1, 0)				
		c = cobj.update(msg)
		c += cobj.final()
		return iv+c

	def dec(self, key, ctxt):
		iv = ctxt[:16]
		cblocks = ctxt[16:]
		cobj = EVP.Cipher('aes_128_cbc', key, iv, 0, 0)				
		ptxt = cobj.update(cblocks)
		ptxt += cobj.final()
		return ptxt

class FixedCBC:
	def __init__(self):
		self.keyset = Bytes(16)
		self.ivset = Bytes(16)

	def keygen(self):
		k = self.keyset.uniform()
		return k
			
	def enc(self, key, msg):
		iv = '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
		cobj = EVP.Cipher('aes_128_cbc', key, iv, 1, 0)				
		c = cobj.update(msg)
		c += cobj.final()
		return iv+c

	def dec(self, key, ctxt):
		iv = ctxt[:16]
		cblocks = ctxt[16:]
		cobj = EVP.Cipher('aes_128_cbc', key, iv, 0, 0)				
		ptxt = cobj.update(cblocks)
		ptxt += cobj.final()
		return ptxt
		

# Games for PRFs

class RandPRFGame:
	
	def __init__(self, D, R):
		self.T = {}
		self.Rng = R
		self.Dmn = D
	
	def Initialize(self):
		return ''

	def Fn(self, x):
		if (self.Dmn.isMember(x) == False):
			return ''
		if (self.T.has_key(x)):
			return self.T[x]
		self.T[x] = self.Rng.uniform()
		return self.T[x]

	def Finalize(self,b):
		return b

class RealPRFGame:
	def __init__(self, PRF):
		self.prf = PRF
		self.K = None
			
	def Initialize(self):
		self.K = self.prf.Keyset.uniform()		
		return ''

	def Fn(self, x):
		if (self.prf.Dmn.isMember(x) == False):
			return ''
		return self.prf.Fun(self.K, x)

	def Finalize(self, b):
		return b




class PRFAdvantage:
	def __init__(self, PRF, adversary):
		self.prf = PRF
		self.adversary = adversary

	def run(self, trials):
		# run real
		adversary = self.adversary
		realones = 0
		for i in range(0, trials):
			self.RealGame = RealPRFGame(self.prf)
			res = self.RealGame.Finalize(adversary.execute(self.RealGame.Initialize(), self.RealGame))
			if (res == 1):
				realones = realones + 1
		
		randones = 0
		#run rand
		for i in range(0, trials):
			self.RandGame = RandPRFGame(self.prf.Dmn, self.prf.Rng)
			res = self.RandGame.Finalize(adversary.execute(self.RandGame.Initialize(), self.RandGame))
			if (res == 1):
				randones = randones + 1
	
		return abs(realones/float(trials) - randones/float(trials))	





# PRFs and PRPs

class XorPRF:
	def __init__(self,n):
		self.Dmn = Bytes(n)
		self.Rng = Bytes(n)
		self.Keyset = Bytes(n)

	def Fun(self, key, x):
		y = [0]*len(key)
		for i in range(0, len(key)):
			y[i] = chr(ord(key[i])^ord(x[i]))
		
		return ''.join(y)



class AES128PRP:
	def __init__(self):
		self.Dmn = Bytes(16)
		self.Rng = Bytes(16)
		self.Keyset = Bytes(16)

	def Fun(self, key, x):
		if (len(x) != 16):
			return ''
		cobj = EVP.Cipher('aes_128_ecb', key, '', 1, 0)				
		return cobj.update(x)

	def Funinv(self, key, y):
		if (len(y) != 16):	
			return ''
		dobj = EVP.Cipher('aes_128_ecb', key, '', 0, 0)				
		# have to trick it into decrypting the first block
		# by giving it something longer than a block
		return dobj.update(y+y)


class ANDPRF:
	def __init__(self,n):
		self.Dmn = Bytes(n)
		self.Rng = Bytes(n)
		self.Keyset = Bytes(n)

	def Fun(self, key, x):
		y = [0]*len(key)
		for i in range(0, len(key)):
			y[i] = chr(ord(key[i])&ord(x[i]))
		
		return ''.join(y)

class AESConcatinate:
	def __init__(self):
		self.Dmn = Bytes(16)
		self.Rng = Bytes(16)
		self.Keyset = Bytes(8)

	def Fun(self, key, x):
		aes = AES128PRP()
		cipher = ''
		hold = 0

		for k in range(0, len(x)/len(key)):
			if(len(key)>len(x)):
				key = key[:len(x)]
			cipher = cipher + aes.Fun(key, x[hold:hold+len(key)])
			hold = hold + len(key)
		
		return cipher

# PRF adversaries


class XorPRFAdv:
	def __init__(self, PRF):
		self.prf = PRF

	def execute(self,initval, Game):
		key = Game.Fn('\x00\x00\x00\x00\x00\x00\x00\x00')
		if (Game.Fn(key) == '\x00\x00\x00\x00\x00\x00\x00\x00'):
			return 1
		return 0


class GuessAdv:
	def __init__(self, PRF):
		self.prf = PRF

	def execute(self,initval, Game):
		flip = Coin()	
		return flip.uniform()


class ANDAdv:
	def __init__(self, PRF):
		self.prf = PRF

	def execute(self,initval, Game):
		key = Game.Fn('\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff')
		if (Game.Fn(key) == key):
			return 1
		return 0

class AESConcatinateAdv:
	def __init__(self, PRF):
		self.prf = PRF

	def execute(self,initval, Game):
		y = Game.Fn(Bytes(16).uniform())
		if(y[:len(y)/2] == y[len(y)/2:]):
			return 1
		return 0

#SE 0 left ---- 1 right


###SE  SCHEMES###

class ManyTimePad:
	def __init__(self):
		self.keyset = Bytes(8)

	def keygen(self):
		k = self.keyset.uniform()
		return k
	
	def enc(self, key, msg):
		cipher = ''
		hold = 0
		xor = XorPRF(8)
		y = [0]*len(key)	

		for k in range(0, len(msg)/len(key)):
			if(len(key)>len(msg)):
				key = key[:len(msg)]
			cipher = cipher + xor.Fun(key, msg[hold:hold+len(key)])
			hold = hold + len(key)
		
		return cipher
			

###Adversaries###
class ManyTimePadAdv:
	def __init__(self, SE):
		self.se = SE
	
	def execute(self, initval, Game):
		M0 = 'aaaaaaaaaaaaaaaaaa'
		M1 = 'bbbbbbbbbbbbbbbbbb'
		y = Game.LR(M0+M0,M0+M1)
		if(y[:len(y)/2] == y[len(y)/2:]):
			
			return 0
		return 1

class ECBAdv:
	def __init__(self, SE):	
		self.se = SE

	def execute(self, initval, Game):
		M0 = 'aaaaaaaaaaaaaaaa'
		M1 = 'bbbbbbbbbbbbbbbb'
		x = Game.LR(M0, M1)
		y = Game.LR(M0, M0)
		if(x==y):
			return 0
		return 1		

class FixedCBCAdv:
	def __init__(self, SE):	
		self.se = SE

	def execute(self, initval, Game):
		M0 = 'aaaaaaaaaaaaaaaa'
		M1 = 'bbbbbbbbbbbbbbbb'
		x = Game.LR(M0, M1)
		y = Game.LR(M0, M0)
		if(x==y):
			return 0
		return 1 

class CBCAdv:
	def __init__(self, SE):
		self.se = SE
	
	def execute(self, initval, Game):
		M0 = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
		M1 = '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
		x = Game.LR(M0, M1)
		iv = x[:16]
		cipher = x[16:]
		ivPrime = [0]*len(iv)
		for i in range(0, len(iv)):
			ivPrime[i] = chr(ord(iv[i])^ord(M1[i]))
		ivPrime = ''.join(ivPrime)
		ctxt = ivPrime + cipher
		decryption = Game.dec(ctxt)
		if (decryption == M0):
			return 1
		return 0

'''
class MACAdv:
	def __init__(self):
		
	
	def execute(self, initval, Game):
		M0 = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
		M1 = '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
		x = Game.LR(M0, M1)
		iv = x[:16]
		cipher = x[16:]
		ivPrime = [0]*len(iv)
		for i in range(0, len(iv)):
			ivPrime[i] = chr(ord(iv[i])^ord(M1[i]))
		ivPrime = ''.join(ivPrime)
		ctxt = ivPrime + cipher
		decryption = Game.dec(ctxt)
		if (decryption == M0):
			return 1
		return 0
'''

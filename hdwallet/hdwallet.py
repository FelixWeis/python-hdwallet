import hashlib, hmac
import base58

from ecdsa import util, numbertheory, ellipticcurve, curves
from curves import SECP256k1

class HDWallet():	
	__chain  = None # ByteSeq
	__pubkey = None # ellipticcurve.Point
	
	__prvkey = None # Int
	__testnet = None 

	__depth    = None
	__parentfp = None
	__childnum = None


	def __init__(self, key, chain, testnet=False, depth=None, parentfp=None, childnum=None):
		
		if type(key) == ellipticcurve.Point: # public key is a point
			self.__pubkey = key	
		elif type(key) == int or type(key) == long: # private key an integer
			assert(0 < key < SECP256k1.order)
			self.__prvkey = key
		else:
			raise TypeError('Unknown key type "{0}"'.format(type(key)))

		assert(len(chain) == 32)
		self.__chain = chain
		self.__testnet = testnet

		assert(depth < 256)

		if depth == None: # master wallet
			depth = 0
			parentfp = '\x00' * 4
			childnum = 0

		self.__depth = depth
		self.__parentfp = parentfp
		self.__childnum = childnum


	def child(self, i):
		assert( 0 <= i <= 2**32-1)
		
		priv_deriv = (i & 0x80000000) != 0

		if (priv_deriv and not self.__prvkey):
			raise Exception('Unable to do private derivation')

		# only allow up to a depth of 255
		assert(self.__depth < 0xff) 
		
		str_i = util.number_to_string(i, 2**32-1)

		if priv_deriv:
			str_k = util.number_to_string(self.__prvkey, SECP256k1.order)
			deriv = hmac.new(key=self.__chain, msg='\x00' + str_k + str_i, digestmod=hashlib.sha512).digest()
		else:
			str_K = point_compress(self.point())
			deriv = hmac.new(key=self.__chain, msg=str_K + str_i, digestmod=hashlib.sha512).digest()

		childChain  = deriv[32:]
		childModifier = util.string_to_number(deriv[:32])

		if childModifier >= SECP256k1.order:
			raise Exception('This is higly unprovable IL >= n, but it did happen')
		
		if self.__prvkey:
			childPrvkey = (self.__prvkey + childModifier) % SECP256k1.order 
			if childPrvkey == 0:
				raise Exception('This is higly unprovable ki = 0, but it did happen')

			childKey = childPrvkey
		else: 
			childPubkey = self.point() + SECP256k1.generator * childModifier
			if childPubkey == ellipticcurve.INFINITY:
				raise Exception('This is higly unprovable Ki = INFINITY, but it did happen')

			childKey = childPubkey

		return self.__class__(childKey, childChain, 
			testnet=self.__testnet,
			depth=self.__depth + 1,
			parentfp=self.fingerprint(),
			childnum=i)


	def to_extended_key(self, include_prv=False):

		if not self.__testnet:
			version = 0x0488B21E if not include_prv else 0x0488ADE4
		else:
			version = 0x043587CF if not include_prv else 0x04358394

		version  = util.number_to_string(version, 2**32-1)
		depth    = util.number_to_string(self.__depth, 2**8-1)
		parentfp = self.parentfp()
		childnum = util.number_to_string(self.__childnum, 2**32-1)
		chaincode = self.__chain
		
		if include_prv:
			if self.__prvkey == None: raise Exception('private key unkown')
			data = '\x00' + util.number_to_string(self.__prvkey, SECP256k1.order)
		else:
			# compress point
			data = point_compress(self.point())
		import base58

		ekdata = ''.join([version, depth, parentfp, childnum, chaincode, data])
		
		checksum=hashlib.sha256(hashlib.sha256(ekdata).digest()).digest()[:4]

		return base58.b58encode(ekdata + checksum)

	def point(self):
		if not self.__pubkey:
			self.__pubkey = SECP256k1.generator * self.__prvkey
		return self.__pubkey


	def pubkey(self):

		x_str = util.number_to_string(self.point().x(), SECP256k1.order)
		y_str = util.number_to_string(self.point().y(), SECP256k1.order)
		return x_str + y_str


	def prvkey(self):
		if self.__prvkey:
			return util.number_to_string(self.__prvkey, SECP256k1.order)
		return None

	def chain(self):
		return self.__chain

	def address(self, versionByte=None):
		if versionByte == None:
			versionByte = '\x00' if not self.__testnet else '\x6F'
		return base58.public_key_to_bc_address(point_compress(self.point()), versionByte)


	def depth(self):
		return self.__depth


	def fingerprint(self):
		return base58.hash_160(point_compress(self.point()))[:4]


	def parentfp(self):
		if self.__depth == 0: # master node has no parent
			return '\x00'*4
		return self.__parentfp


	def childnum(self):
		return self.__childnum


	@classmethod
	def from_extended_key(klass, extended_key):
		decoded = base58.b58decode(extended_key, 78+4)
		assert(decoded)
		ekdata = decoded[:78]
		checksum = decoded[78:78+4]
		# validate checksum
		valid_checksum = hashlib.sha256(hashlib.sha256(ekdata).digest()).digest()[:4]
		assert (checksum == valid_checksum)

		
		version = util.string_to_number(ekdata[0:0+4])
		depth   = util.string_to_number(ekdata[4:4+1])
		parentfp = ekdata[5:5+4]
		childnum = util.string_to_number(ekdata[9:9+4])
		chaincode = ekdata[13:13+32]
		data = ekdata[45:45+33]

		testnet = version in (0x043587CF, 0x04358394)
		
		if version in (0x0488B21E, 0x043587CF): # data contains pubkey
			assert data[0] in ('\x02', '\x03')
			key = point_decompress(SECP256k1.curve, data)
		elif version in (0x0488ADE4, 0x04358394): # data contains privkey
			assert data[0] == '\x00'
			key = util.string_to_number(data[1:])
		else:
			raise Exception('unknown version')

		return klass(key, chaincode, 
			testnet=testnet,
			depth=depth,
			childnum=childnum,
			parentfp=parentfp)


	@classmethod
	def from_master_seed(klass, master_seed, testnet=False):
		deriv = hmac.new(key='Bitcoin seed', msg=master_seed, digestmod=hashlib.sha512).digest()
		master_key = util.string_to_number(deriv[:32]) % SECP256k1.order
		master_chain = deriv[32:]
		return klass(master_key, master_chain, testnet=testnet)


def point_compress(point):
	x = point.x()
	y = point.y()
	curve = point.curve()

	return chr(2 + (y & 1)) + util.number_to_string(x, curve.p())


def point_decompress(curve, data):
	prefix = data[0]
	assert(prefix in ['\x02', '\x03'])
	parity = 1 if prefix == '\x02' else -1

	x = util.string_to_number(data[1:])

	y = numbertheory.square_root_mod_prime( 
	  ( x * x * x + curve.a() * x + curve.b() ) % curve.p(),  curve.p()
	)

	y = parity * y % curve.p()
	return ellipticcurve.Point(curve, x, y)



def main():
	# 1. generate a master wallet with a (random) seed 
	master = HDWallet.from_master_seed('HDWallet seed')
	# 2. store the Private Extended Key somewhere very (!) safe
	prv_master_key = master.to_extended_key(include_prv=True)
	# 3. store the Public Extended Key on the webserver
	pub_master_key = master.to_extended_key()



	# 4. On the webserver we can generate child wallets, 
	webserver_wallet = HDWallet.from_extended_key(pub_master_key)
	child2342 = webserver_wallet.child(23).child(42)
	print '- Public Extended Key (M):', pub_master_key
	print 'Child: M/23/42'
	print 'Address:', child2342.address()
	print 'Privkey:', child2342.prvkey() # ... but the private keys remain _unknown_
	print ''


	# 5. In case we need the private key for a child wallet, start with the private master key
	cold_wallet = HDWallet.from_extended_key(prv_master_key)
	child2342 = cold_wallet.child(23).child(42)
	print '- Private Extended Key (m):', prv_master_key
	print 'Child: m/23/42'
	print 'Address:', child2342.address()
	print 'Privkey:', child2342.prvkey().encode('hex')

if __name__ == "__main__":
	main()

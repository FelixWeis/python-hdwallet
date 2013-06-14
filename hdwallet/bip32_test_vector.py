#!/usr/bin/env python

import base58
import hashlib

from curves import *
from hdwallet import HDWallet, point_compress

Hash = lambda x: hashlib.sha256(hashlib.sha256(x).digest()).digest()
def EncodeBase58Check(vchIn):
    hash = Hash(vchIn)
    return base58.b58encode(vchIn + hash[0:4])

def SecretToASecret(secret, compressed=False, addrtype=0):
    vchIn = chr((addrtype+128)&255) + secret
    if compressed: vchIn += '\01'
    return EncodeBase58Check(vchIn)

def print_info(key, desc):
  
  prv_key = key.to_extended_key(include_prv=key.prvkey() is not None)
  pub_key = key.to_extended_key()

  print desc
  print '    * Identifier'
  print '      * (hex):       %s' % base58.hash_160(point_compress(key.point())).encode('hex')
  print '      * (fpr):       0x%s' % key.fingerprint().encode('hex')
  print '      * (main addr): %s' % key.address()
  print '    * Secret key'
  print '      * (hex):       %s' % (key.prvkey().encode('hex') if key.prvkey() is not None else 'n/a')
  print '      * (wif):       %s' % (SecretToASecret(key.prvkey(), True) if key.prvkey() is not None else 'n/a')
  print '    * Public key'
  print '      * (hex):       %s' % point_compress(key.point()).encode('hex')
  print '    * Chain code'
  print '      * (hex):       %s' % key.chain().encode('hex')
  print '    * Serialized'
  print '      * (pub hex):   %s' % base58.b58decode(pub_key, None).encode('hex')
  print '      * (prv hex):   %s' % base58.b58decode(prv_key, None).encode('hex')
  print '      * (pub b58):   %s' % pub_key
  print '      * (prv b58):   %s' % prv_key

def main():
  seed = '000102030405060708090a0b0c0d0e0f'

  print '* Master (hex): %s' % seed

  master = HDWallet.from_master_seed(seed.decode('hex'))
  print_info(master, '  * [Chain m]')

  ch = master.child(0x80000000)
  print_info(ch, '  * [Chain m/0\']')

  ch = ch.child(1)
  print_info(ch, '  * [Chain m/0\'/1]')

  # ch = ch.child(0x80000002)
  # print_info(ch, '  * [Chain m/0\'/1/2\']')

  # ch = ch.child(2)
  # print_info(ch, '  * [Chain m/0\'/1/2\'/2]')

  # ch = ch.child(1000000000)
  # print_info(ch, '  * [Chain m/0\'1/2\'/2/0\']')


if __name__ == "__main__":
  main()
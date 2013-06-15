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

def print_info(key, chain):
  
  prv_key = key.to_extended_key(include_prv=key.prvkey())
  pub_key = key.to_extended_key()

  desc ='  * [Chain m'
  for c in chain:
    if c&0x80000000:
      desc = desc + '/%d\'' % (c & ~0x80000000)
    else:
      desc = desc + '/%d' % c
  desc = desc + ']'

  print desc

  print '    * Identifier'
  print '      * (hex):       %s' % base58.hash_160(point_compress(key.point())).encode('hex')
  print '      * (fpr):       0x%s' % key.fingerprint().encode('hex')
  print '      * (main addr): %s' % key.address()
  print '    * Secret key'
  print '      * (hex):       %s' % key.prvkey().encode('hex')
  print '      * (wif):       %s' % SecretToASecret(key.prvkey(), True)
  print '    * Public key'
  print '      * (hex):       %s' % point_compress(key.point()).encode('hex')
  print '    * Chain code'
  print '      * (hex):       %s' % key.chain().encode('hex')
  print '    * Serialized'
  print '      * (pub hex):   %s' % base58.b58decode(pub_key, None).encode('hex')
  print '      * (prv hex):   %s' % base58.b58decode(prv_key, None).encode('hex')
  print '      * (pub b58):   %s' % pub_key
  print '      * (prv b58):   %s' % prv_key


def test_vector(seed, seq):
  print '* Master (hex): %s' % seed

  current = HDWallet.from_master_seed(seed.decode('hex'))
  print_info(current, [])
  
  for i in xrange(len(seq)):
    current = current.child(seq[i])
    print_info(current, seq[:i+1])


def main():

  # --- test vector 1
  seed = '000102030405060708090a0b0c0d0e0f'
  seq = [0x80000000, 1, 0x80000002, 2, 1000000000]
  print '---- Test Vector 1 ----'
  test_vector(seed, seq)

  # --- test vector 2
  seed = 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542'
  seq = [0, 0xFFFFFFFF, 1, 0xFFFFFFFE, 2]
  print '---- Test Vector 2 ----'
  test_vector(seed, seq)

if __name__ == "__main__":
  main()
from ecdsa import ellipticcurve
from ecdsa.curves import Curve

# Certicom secp256-k1
_a  = 0x0000000000000000000000000000000000000000000000000000000000000000L
_b  = 0x0000000000000000000000000000000000000000000000000000000000000007L
_p  = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fL
_Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798L
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L
_r  = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141L

curve_secp256k1 = ellipticcurve.CurveFp( _p, _a, _b)
generator_secp256k1 = ellipticcurve.Point( curve_secp256k1, _Gx, _Gy, _r)

SECP256k1 = Curve("SECP256k1",
                  curve_secp256k1, generator_secp256k1,
                  (1, 3, 132, 0, 10))
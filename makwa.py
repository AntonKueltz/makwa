from binascii import hexlify
from hashlib import sha256
import hmac
from os import urandom
from struct import pack


def int_to_bytes(i):
    bs = b''
    while i != 0:
        bs = pack('=B', i & 0xff) + bs
        i >>= 8
    return bs


class Makwa:
    def __init__(self, password, salt=None, h=sha256, work_factor=4096, pre_hashing=True):
        self.password = bytes(password)
        self.h = h
        if salt == None:
            salt = urandom(16)
        self.salt = bytes(salt)
        if work_factor == 0:
            raise ValueError('Work factor cannot be 0')
        self.m_cost = work_factor
        self.pre_hashing = pre_hashing
        self.post_hashing_length = 12

    def digest(self, n):
        if self.m_cost == 0:
            raise ValueError('Work factor cannot be 0') 
        k = (n.bit_length() + 7) // 8
        if k < 160:
            raise ValueError('Modulus must be >= 160 bits')

        if self.pre_hashing:
            self.password = self._kdf(self.password, 64)

        u = len(self.password)
        if u > 255 or u > (k -32):
            raise ValueError('Password is to long to be hashed under these parameters')
        sb = self._kdf(self.salt + self.password + pack('=B', u), k - 2 - u)
        xb = b'\x00' + sb + self.password + pack('=B', u)

        x = int(hexlify(xb), 16)
        for _ in range(self.m_cost+1):
            x = pow(x, 2, n)
        out = int_to_bytes(x) 

        if self.post_hashing_length > 0:
            out = self._kdf(out, self.post_hashing_length)

        return out

    def _kdf(self, data, out_len):
        r = self.h().digest_size
        V = b'\x01' * r
        K = b'\x00' * r
        K = hmac.new(K, msg=(V + b'\x00' + data), digestmod=self.h).digest()
        V = hmac.new(K, msg=V, digestmod=self.h).digest()
        K = hmac.new(K, msg=(V + b'\x01' + data), digestmod=self.h).digest()
        V = hmac.new(K, msg=V, digestmod=self.h).digest()
        T = b''
        while len(T) < out_len:
            V = hmac.new(K, msg=V, digestmod=self.h).digest()
            T += V
        return T[:out_len]


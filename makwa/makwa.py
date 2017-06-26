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
    def __init__(self, h=sha256, work_factor=4096, pre_hashing=True):
        self.h = h
        if work_factor == 0:
            raise ValueError('Work factor cannot be 0')
        self.m_cost = work_factor
        self.pre_hashing = pre_hashing
        self.post_hashing_length = 12

    def hash(self, password, n, salt=None,):
        password = bytes(password)
        if salt is None:
            salt = urandom(16)
        h = ''
        h += self._base64(self._kdf(int_to_bytes(n), 8))
        h += '_'
        h += self._state_data()
        h += '_'
        h += self._base64(salt)
        h += '_'
        h += self._base64(self.digest(password, n, salt=salt))
        return h

    def digest(self, password, n, salt=None,):
        password = bytes(password)
        if salt is None:
            salt = urandom(16)

        if self.m_cost == 0:
            raise ValueError('Work factor cannot be 0')
        k = (n.bit_length() + 7) // 8
        if k < 160:
            raise ValueError('Modulus must be >= 160 bits')

        if self.pre_hashing:
            password = self._kdf(password, 64)

        u = len(password)
        if u > 255 or u > (k - 32):
            raise ValueError('Password is to long to be hashed under these parameters')
        sb = self._kdf(salt + password + pack('=B', u), k - 2 - u)
        xb = b'\x00' + sb + password + pack('=B', u)

        x = int(hexlify(xb), 16)
        for _ in range(self.m_cost + 1):
            x = pow(x, 2, n)
        out = int_to_bytes(x)

        if self.post_hashing_length not in [0, None]:
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

    def _base64(self, M):
        M_ = M + (b'\x00' * ((3 - (len(M) % 3)) % 3))

        B_ = ''
        for i in range(0, len(M_), 3):
            mi = M_[i:(i + 3)]
            B_ += self._encode_sequence(mi)

        return B_[:(4 * (len(M_) // 3) - (-len(M) % 3))]

    def _state_data(self):
        ret = ''

        pre, post = self.pre_hashing, self.post_hashing_length
        if not pre and not post:
            ret += 's'
        elif pre and not post:
            ret += 'r'
        elif not pre and post:
            ret += 's'
        else:
            ret += 'b'

        delta, w = 0, self.m_cost
        while w & 1 == 0:
            delta += 1
            w //= 2

        ret += '2' if w == 1 else '3'
        ret += str(delta - 1) if w == 1 else str(delta)
        return ret

    def _encode_sequence(self, b):
        b1, b2, b3 = b[0], b[1], b[2]
        if not any([isinstance(b1, int), isinstance(b2, int), isinstance(b3, int)]):
            b1, b2, b3 = ord(b1), ord(b2), ord(b3)

        d1 = b1 // 4
        d2 = 16 * (b1 % 4) + b2 // 16
        d3 = 4 * (b2 % 16) + b3 // 64
        d4 = b3 % 64
        encoding = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' \
                   'abcdefghijklmnopqrstuvwxyz' \
                   '0123456789+/'
        return ''.join(map(lambda d: encoding[d], [d1, d2, d3, d4]))

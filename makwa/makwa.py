from binascii import a2b_base64, b2a_base64, hexlify
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


def hashpw(password, n, salt=None, h=sha256, work_factor=4096, pre_hashing=True):
    makwa = Makwa(h=h, work_factor=work_factor, pre_hashing=pre_hashing)
    return makwa.hash(password, n, salt=salt)


def checkpw(password, hashed_password, n, h=sha256):
    state = hashed_password.split('_')[1]
    work_factor = int(state[1]) * (1 << int(state[2:]))
    pre_hashing = state[0] in 'rb'
    makwa = Makwa(h=h, work_factor=work_factor, pre_hashing=pre_hashing)
    return makwa.check(password, hashed_password, n)


class Makwa:
    def __init__(self, h=sha256, work_factor=4096, pre_hashing=True):
        self.h = h
        if work_factor == 0:
            raise ValueError('Work factor cannot be 0')
        self.m_cost = work_factor
        self.pre_hashing = pre_hashing
        self.post_hashing_length = 12

    def hash(self, password, n, salt=None,):
        if not isinstance(password, bytes):
            raise TypeError('Unicode-objects must be encoded before hashing')
        if salt is None:
            salt = urandom(16)

        h = ''
        h += self._base64(self._kdf(int_to_bytes(n), 8))
        h += '_'
        h += self._state_data()
        h += '_'
        h += self._base64(salt)
        h += '_'
        h += self._base64(self._digest(password, n, salt=salt))
        return h

    def check(self, password, hashed_password, n):
        if not isinstance(password, bytes):
            raise TypeError('Unicode-objects must be encoded before hashing')

        modhash, state, salt, digest = hashed_password.split('_')
        modhash = self._unbase64(modhash)
        salt = self._unbase64(salt)
        digest = self._unbase64(digest)

        if self._kdf(int_to_bytes(n), 8) != modhash:
            return False

        check_digest = self._digest(password, n, salt=salt)
        return digest == check_digest

    def _digest(self, password, n, salt=None,):
        if not isinstance(password, bytes):
            raise TypeError('Unicode-objects must be encoded before hashing')
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

    def _base64(self, m):
        b64 = b2a_base64(m)
        if not isinstance(b64, str):
            b64 = b64.decode()
        return b64.replace('=', '').replace('\n', '')

    def _unbase64(self, m):
        padding = ((3 - (len(m) % 3)) % 3) * '='
        return a2b_base64(m + padding)

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

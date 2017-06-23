from hashlib import sha256
import hmac


class Makwa:
    def __init__(self, h=sha256):
        self.h = h

    def _kdf(self, data, out_len):
        r = h().digestsize
        V = '\x01' * r
        K = '\x00' * r
        K = hmac.new(K, msg=(V + '\x00' + data), digestmod=self.h).digest()
        V = hmac.new(K, msg=V, digestmod=h).digest()
        K = hmac.new(K, msg=(V + '\x01' + data), digestmod=self.h).digest()
        V = hmac.new(K, msg=V, digestmod=h).digest()
        T = ''
        while len(T) < out_len:
            V = hmac.new(K, msg=V, digestmod=h).digest()
            T += V
        return T[:out_len]


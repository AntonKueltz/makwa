from binascii import hexlify, unhexlify
from hashlib import sha512
from random import sample
from re import findall
from six import b
import unittest

from .makwa import Makwa, hashpw, checkpw

n = int(
    'C22C40BBD056BB213AAD7C830519101AB926AE18E3E9FC9699C806E0AE5C2594'
    '14A01AC1D52E873EC08046A68E344C8D74A508952842EF0F03F71A6EDC077FAA'
    '14899A79F83C3AE136F774FA6EB88F1D1AEA5EA02FC0CCAF96E2CE86F3490F49'
    '93B4B566C0079641472DEFC14BECCF48984A7946F1441EA144EA4C802A457550'
    'BA3DF0F14C090A75FE9E6A77CF0BE98B71D56251A86943E719D27865A489566C'
    '1DC57FCDEFACA6AB043F8E13F6C0BE7B39C92DA86E1D87477A189E73CE8E311D'
    '3D51361F8B00249FB3D8435607B14A1E70170F9AF36784110A3F2E67428FC18F'
    'B013B30FE6782AECB4428D7C8E354A0FBD061B01917C727ABEE0FE3FD3CEF761',
    16
)


class MakwaTest(unittest.TestCase):
    def test_spec_vector(self):
        pi = unhexlify(
            '4765676F206265736877616A692761616B656E20617765206D616B77613B206F6'
            'E7A61616D206E616E69697A61616E697A692E'
        )
        sigma = unhexlify('C72703C22A96D9992F3DEA876497E392')

        makwa = Makwa(work_factor=4096, pre_hashing=False)
        digest = makwa._digest(pi, n, salt=sigma)
        self.assertEqual(hexlify(digest), b'c9cea0e6ef09393ab1710a08')

        h = makwa.hash(pi, n, salt=sigma)
        self.assertEqual(h, '+RK3n5jz7gs_s211_xycDwiqW2ZkvPeqHZJfjkg_yc6g5u8JOTqxcQoI')

        h = hashpw(pi, n, salt=sigma, work_factor=4096, pre_hash=False)
        self.assertEqual(h, '+RK3n5jz7gs_s211_xycDwiqW2ZkvPeqHZJfjkg_yc6g5u8JOTqxcQoI')
        self.assertEqual(h, '+RK3n5jz7gs_s211_xycDwiqW2ZkvPeqHZJfjkg_yc6g5u8JOTqxcQoI')

        self.assertTrue(makwa.check(pi, h, n))
        self.assertTrue(checkpw(pi, h, n))

        self.assertFalse(makwa.check(b'password', h, n))
        self.assertFalse(checkpw(b'password', h, n))

        self.assertFalse(makwa.check(pi, h, 0xbadc0de))
        self.assertFalse(checkpw(pi, h, 0xbadc0de))

    def test_kdf_sha256(self):
        m = Makwa()
        matches = []

        with open('kat.txt', 'r') as f:
            pattern = r'KDF/SHA-256\n' \
                'input: ([a-f0-9]*)\n' \
                'output: ([a-f0-9]*)'
            matches = findall(pattern, f.read())

        for (input, output) in sample(matches, 100):
            result = hexlify(m._kdf(unhexlify(input), 100))
            self.assertEqual(result, b(output))

    def test_kdf_sha512(self):
        m = Makwa(h=sha512)
        matches = []

        with open('kat.txt', 'r') as f:
            pattern = r'KDF/SHA-512\n' \
                'input: ([a-f0-9]*)\n' \
                'output: ([a-f0-9]*)'
            matches = findall(pattern, f.read())

        for (input, output) in sample(matches, 100):
            result = hexlify(m._kdf(unhexlify(input), 100))
            self.assertEqual(result, b(output))

    def test_digest_sha256(self):
        matches = []

        with open('kat.txt', 'r') as f:
            pattern = r'2048-bit modulus, SHA-256\n' \
                'input: ([a-f0-9]*)\n' \
                'salt: ([a-f0-9]*)\n' \
                'pre-hashing: (.*)\n' \
                'post-hashing: (.*)\n' \
                'bin384: ([a-f0-9]*)\n' \
                'bin4096: ([a-f0-9]*)'
            matches = findall(pattern, f.read())

        for (input, salt, pre_hashing, post_hashing, bin384, bin4096) in sample(matches, 100):
            pre_hashing = (pre_hashing == 'true')
            post_hashing = (None if post_hashing == 'false' else int(post_hashing))
            m = Makwa(
                work_factor=384,
                pre_hashing=pre_hashing,
                post_hashing_length=post_hashing
            )
            digest = m._digest(unhexlify(input), n, unhexlify(salt))
            self.assertEqual(hexlify(digest), b(bin384))

            m = Makwa(
                work_factor=4096,
                pre_hashing=pre_hashing,
                post_hashing_length=post_hashing
            )
            digest = m._digest(unhexlify(input), n, unhexlify(salt))
            self.assertEqual(hexlify(digest), b(bin4096))

    def test_digest_sha512(self):
        matches = []

        with open('kat.txt', 'r') as f:
            pattern = r'2048-bit modulus, SHA-512\n' \
                'input: ([a-f0-9]*)\n' \
                'salt: ([a-f0-9]*)\n' \
                'pre-hashing: (.*)\n' \
                'post-hashing: (.*)\n' \
                'bin384: ([a-f0-9]*)\n' \
                'bin4096: ([a-f0-9]*)'
            matches = findall(pattern, f.read())

        for (input, salt, pre_hashing, post_hashing, bin384, bin4096) in sample(matches, 100):
            pre_hashing = (pre_hashing == 'true')
            post_hashing = (None if post_hashing == 'false' else int(post_hashing))
            m = Makwa(
                h=sha512,
                work_factor=384,
                pre_hashing=pre_hashing,
                post_hashing_length=post_hashing
            )
            digest = m._digest(unhexlify(input), n, unhexlify(salt))
            self.assertEqual(hexlify(digest), b(bin384))

            m = Makwa(
                h=sha512,
                work_factor=4096,
                pre_hashing=pre_hashing,
                post_hashing_length=post_hashing
            )
            digest = m._digest(unhexlify(input), n, unhexlify(salt))
            self.assertEqual(hexlify(digest), b(bin4096))

    def test_hashpw_sha256(self):
        matches = []

        with open('kat.txt', 'r') as f:
            pattern = r'2048-bit modulus, SHA-256\n' \
                'input: ([a-f0-9]*)\n' \
                'salt: ([a-f0-9]*)\n' \
                'pre-hashing: (.*)\n' \
                'post-hashing: (.*)\n' \
                'bin384: [a-f0-9]*\n' \
                'bin4096: [a-f0-9]*\n' \
                'str384: ([A-Za-z0-9\+\/\_]*)\n' \
                'str4096: ([A-Za-z0-9\+\/\_]*)'
            matches = findall(pattern, f.read())

        for (input, salt, pre_hashing, post_hashing, str384, str4096) in sample(matches, 100):
            pre_hashing = (pre_hashing == 'true')
            post_hashing = (None if post_hashing == 'false' else int(post_hashing))
            hashed = hashpw(
                unhexlify(input),
                n,
                salt=unhexlify(salt),
                work_factor=384,
                pre_hash=pre_hashing,
                post_hash=post_hashing
            )
            self.assertEqual(hashed, str384)
            self.assertTrue(checkpw(unhexlify(input), hashed, n))

            hashed = hashpw(
                unhexlify(input),
                n,
                salt=unhexlify(salt),
                work_factor=4096,
                pre_hash=pre_hashing,
                post_hash=post_hashing
            )
            self.assertEqual(hashed, str4096)
            self.assertTrue(checkpw(unhexlify(input), hashed, n))

    def test_hashpw_sha512(self):
        matches = []

        with open('kat.txt', 'r') as f:
            pattern = r'2048-bit modulus, SHA-512\n' \
                'input: ([a-f0-9]*)\n' \
                'salt: ([a-f0-9]*)\n' \
                'pre-hashing: (.*)\n' \
                'post-hashing: (.*)\n' \
                'bin384: [a-f0-9]*\n' \
                'bin4096: [a-f0-9]*\n' \
                'str384: ([A-Za-z0-9\+\/\_]*)\n' \
                'str4096: ([A-Za-z0-9\+\/\_]*)'
            matches = findall(pattern, f.read())

        for (input, salt, pre_hashing, post_hashing, str384, str4096) in sample(matches, 100):
            pre_hashing = (pre_hashing == 'true')
            post_hashing = (None if post_hashing == 'false' else int(post_hashing))
            hashed = hashpw(
                unhexlify(input),
                n,
                salt=unhexlify(salt),
                h=sha512,
                work_factor=384,
                pre_hash=pre_hashing,
                post_hash=post_hashing
            )
            self.assertEqual(hashed, str384)
            self.assertTrue(checkpw(unhexlify(input), hashed, n, h=sha512))

            hashed = hashpw(
                unhexlify(input),
                n,
                salt=unhexlify(salt),
                h=sha512,
                work_factor=4096,
                pre_hash=pre_hashing,
                post_hash=post_hashing
            )
            self.assertEqual(hashed, str4096)
            self.assertTrue(checkpw(unhexlify(input), hashed, n, h=sha512))


if __name__ == '__main__':
    unittest.main()

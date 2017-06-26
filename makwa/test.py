from binascii import hexlify, unhexlify
import unittest

from .makwa import Makwa


class MakwaTest(unittest.TestCase):

    def test_spec_vector(self):
        pi = unhexlify(
            '4765676F206265736877616A692761616B656E20617765206D616B77613B206F6'
            'E7A61616D206E616E69697A61616E697A692E'
        )
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
        sigma = unhexlify('C72703C22A96D9992F3DEA876497E392')

        makwa = Makwa(work_factor=4096, pre_hashing=False)
        digest = makwa.digest(pi, n, salt=sigma)
        self.assertEqual(hexlify(digest), b'c9cea0e6ef09393ab1710a08')
        h = makwa.hash(pi, n, salt=sigma)
        self.assertEqual(h, '+RK3n5jz7gs_s211_xycDwiqW2ZkvPeqHZJfjkg_yc6g5u8JOTqxcQoI')


if __name__ == '__main__':
    unittest.main()

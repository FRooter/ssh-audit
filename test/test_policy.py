import hashlib
import pytest
from datetime import date


class TestPolicy:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.Policy = ssh_audit.Policy
        self.wbuf = ssh_audit.WriteBuf
        self.ssh2 = ssh_audit.SSH2


    # Ensure that a basic policy can be parsed correctly.
    def test_policy_basic(self):
        pol_data = []
        pol_data.append('# This is a comment')
        pol_data.append('name = "Test Policy"')
        pol_data.append('version = 1')
        pol_data.append('')  # Blank line that should be ignored.
        pol_data.append('compressions = comp_alg1')
        pol_data.append('host keys = key_alg1')
        pol_data.append('key exchanges = kex_alg1, kex_alg2')
        pol_data.append('ciphers = cipher_alg1, cipher_alg2, cipher_alg3')
        pol_data.append('macs = mac_alg1, mac_alg2, mac_alg3')

        policy = self.Policy(policy_data=pol_data)
        assert str(policy) == "Name: [Test Policy]\nVersion: [1]\nBanner: {undefined}\nHeader: {undefined}\nCompressions: comp_alg1\nHost Keys: key_alg1\nKey Exchanges: kex_alg1, kex_alg2\nCiphers: cipher_alg1, cipher_alg2, cipher_alg3\nMACs: mac_alg1, mac_alg2, mac_alg3"


    # Basic policy, but with 'ciphersx' instead of 'ciphers'.
    def test_policy_invalid_1(self):
        pol_data = []
        pol_data.append('# This is a comment')
        pol_data.append('name = "Test Policy"')
        pol_data.append('version = 1')
        pol_data.append('')  # Blank line that should be ignored.
        pol_data.append('compressions = comp_alg1')
        pol_data.append('host keys = key_alg1')
        pol_data.append('key exchanges = kex_alg1, kex_alg2')
        pol_data.append('ciphersx = cipher_alg1, cipher_alg2, cipher_alg3')
        pol_data.append('macs = mac_alg1, mac_alg2, mac_alg3')

        failed = False
        try:
            policy = self.Policy(policy_data=pol_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    # Basic policy, but is missing the required name field.
    def test_policy_invalid_2(self):
        pol_data = []
        pol_data.append('# This is a comment')
        pol_data.append('#name = "Test Policy"')
        pol_data.append('version = 1')
        pol_data.append('')  # Blank line that should be ignored.
        pol_data.append('compressions = comp_alg1')
        pol_data.append('host keys = key_alg1')
        pol_data.append('key exchanges = kex_alg1, kex_alg2')
        pol_data.append('ciphers = cipher_alg1, cipher_alg2, cipher_alg3')
        pol_data.append('macs = mac_alg1, mac_alg2, mac_alg3')

        failed = False
        try:
            policy = self.Policy(policy_data=pol_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    # Basic policy, but is missing the required version field.
    def test_policy_invalid_3(self):
        pol_data = []
        pol_data.append('# This is a comment')
        pol_data.append('name = "Test Policy"')
        pol_data.append('#version = 1')
        pol_data.append('')  # Blank line that should be ignored.
        pol_data.append('compressions = comp_alg1')
        pol_data.append('host keys = key_alg1')
        pol_data.append('key exchanges = kex_alg1, kex_alg2')
        pol_data.append('ciphers = cipher_alg1, cipher_alg2, cipher_alg3')
        pol_data.append('macs = mac_alg1, mac_alg2, mac_alg3')

        failed = False
        try:
            policy = self.Policy(policy_data=pol_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    # Basic policy, but is missing quotes in the name field.
    def test_policy_invalid_4(self):
        pol_data = []
        pol_data.append('# This is a comment')
        pol_data.append('name = Test Policy')
        pol_data.append('version = 1')
        pol_data.append('')  # Blank line that should be ignored.
        pol_data.append('compressions = comp_alg1')
        pol_data.append('host keys = key_alg1')
        pol_data.append('key exchanges = kex_alg1, kex_alg2')
        pol_data.append('ciphers = cipher_alg1, cipher_alg2, cipher_alg3')
        pol_data.append('macs = mac_alg1, mac_alg2, mac_alg3')

        failed = False
        try:
            policy = self.Policy(policy_data=pol_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    # Basic policy, but is missing quotes in the banner field.
    def test_policy_invalid_5(self):
        pol_data = []
        pol_data.append('# This is a comment')
        pol_data.append('name = "Test Policy"')
        pol_data.append('version = 1')
        pol_data.append('')  # Blank line that should be ignored.
        pol_data.append('banner = 0mg')
        pol_data.append('compressions = comp_alg1')
        pol_data.append('host keys = key_alg1')
        pol_data.append('key exchanges = kex_alg1, kex_alg2')
        pol_data.append('ciphers = cipher_alg1, cipher_alg2, cipher_alg3')
        pol_data.append('macs = mac_alg1, mac_alg2, mac_alg3')

        failed = False
        try:
            policy = self.Policy(policy_data=pol_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    # Basic policy, but is missing quotes in the header field.
    def test_policy_invalid_6(self):
        pol_data = []
        pol_data.append('# This is a comment')
        pol_data.append('name = "Test Policy"')
        pol_data.append('version = 1')
        pol_data.append('')  # Blank line that should be ignored.
        pol_data.append('header = 0mg')
        pol_data.append('compressions = comp_alg1')
        pol_data.append('host keys = key_alg1')
        pol_data.append('key exchanges = kex_alg1, kex_alg2')
        pol_data.append('ciphers = cipher_alg1, cipher_alg2, cipher_alg3')
        pol_data.append('macs = mac_alg1, mac_alg2, mac_alg3')

        failed = False
        try:
            policy = self.Policy(policy_data=pol_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    def test_policy_create_1(self):
        w = self.wbuf()
        w.write(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff')
        w.write_list(['kex_alg1', 'kex_alg2'])
        w.write_list(['key_alg1', 'key_alg2'])
        w.write_list(['cipher_alg1', 'cipher_alg2', 'cipher_alg3'])
        w.write_list(['cipher_alg1', 'cipher_alg2', 'cipher_alg3'])
        w.write_list(['mac_alg1', 'mac_alg2', 'mac_alg3'])
        w.write_list(['mac_alg1', 'mac_alg2', 'mac_alg3'])
        w.write_list(['comp_alg1', 'comp_alg2'])
        w.write_list(['comp_alg1', 'comp_alg2'])
        w.write_list([''])
        w.write_list([''])
        w.write_byte(False)
        w.write_int(0)
        kex = self.ssh2.Kex.parse(w.write_flush())
        pol_data = self.Policy.create('www.l0l.com', 'bannerX', 'headerX', kex)

        # Today's date is embedded in the policy, so filter it out to get repeatable results.
        today = date.today().strftime('%Y/%m/%d')
        pol_data = pol_data.replace(today, '[todays date]')

        #assert pol_data == 'x'
        assert hashlib.sha256(pol_data.encode('ascii')).hexdigest() == 'e830fb9e5731995e5e4858b2b6d16704d7e5c2769d3a8d9acdd023a83ab337c5'

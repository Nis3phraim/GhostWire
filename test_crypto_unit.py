"""Unit tests for shared/crypto.py (unittest — no pytest dependency).

Run:  python3 -m unittest test_crypto_unit -v

Covers the 2026-11-16 review ask: cryptographic unit tests for the existing
implementation. Includes tamper/non-detection tests that DOCUMENT the known
CTR limitation (no integrity) rather than silently passing over it.
"""
import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared.crypto import AESCipher, RSAKeyManager, generate_session_key


class TestAESCipher(unittest.TestCase):
    def setUp(self):
        self.key = generate_session_key()
        self.aes = AESCipher(self.key)

    def test_roundtrip_str(self):
        msg = "whoami && id"
        self.assertEqual(self.aes.decrypt(self.aes.encrypt(msg)), msg)

    def test_roundtrip_bytes_and_unicode(self):
        for msg in (b"\x00\x01binary", "unicode: שלום"):
            self.assertEqual(self.aes.decrypt(self.aes.encrypt(msg)),
                             msg if isinstance(msg, str) else msg.decode())

    def test_random_iv_unique_ciphertext(self):
        self.assertNotEqual(self.aes.encrypt("same"), self.aes.encrypt("same"))

    def test_iv_prepended_16_bytes(self):
        raw = base64.b64decode(self.aes.encrypt("abcd"))
        self.assertEqual(len(raw), 16 + 4)

    def test_key_length_validated(self):
        for bad in (b"", os.urandom(16), os.urandom(31), os.urandom(33)):
            with self.assertRaises(ValueError):
                AESCipher(bad)

    def test_wrong_key_no_error_wrong_plaintext(self):
        """CTR has no authentication: decrypting with the WRONG key raises no
        cryptographic error. Either it returns garbage silently, or the
        incidental .decode('utf-8') fails on invalid bytes — an encoding
        accident, not an integrity check. Assert that and only that."""
        other = AESCipher(generate_session_key())
        ct = self.aes.encrypt("secret tasking")
        try:
            wrong = other.decrypt(ct)      # no crypto error raised
        except UnicodeDecodeError:
            wrong = None                   # incidental, not authentication
        self.assertNotEqual(wrong, "secret tasking")

    def test_bitflip_undetected(self):
        """Flipping one ciphertext bit flips the corresponding plaintext bit
        with NO error — the exact malleability documented in the README.
        If this test ever fails because decrypt() starts raising, the module
        gained integrity protection and the docs should be updated too."""
        ct = bytearray(base64.b64decode(self.aes.encrypt("transfer 100.00")))
        ct[20] ^= 0x01                      # one bit in the body (past the IV)
        tampered = base64.b64encode(bytes(ct)).decode()
        out = self.aes.decrypt(tampered)   # silent — no integrity check exists
        self.assertNotEqual(out, "transfer 100.00")
        self.assertEqual(len(out), len("transfer 100.00"))  # CTR preserves length

    def test_malformed_input_raises(self):
        with self.assertRaises(Exception):
            self.aes.decrypt("!!!not-base64!!!")


class TestRSAKeyExchange(unittest.TestCase):
    def test_roundtrip_ephemeral_keys(self):
        priv, pub = RSAKeyManager.generate_keys()
        session = generate_session_key()
        wrapped = RSAKeyManager.encrypt_key(session, pub)
        self.assertEqual(RSAKeyManager.decrypt_key(wrapped, priv), session)

    def test_wrong_private_key_rejected(self):
        _, pub = RSAKeyManager.generate_keys()
        wrong_priv, _ = RSAKeyManager.generate_keys()
        wrapped = RSAKeyManager.encrypt_key(generate_session_key(), pub)
        with self.assertRaises(ValueError):   # OAEP padding check fails
            RSAKeyManager.decrypt_key(wrapped, wrong_priv)

    def test_session_key_shape(self):
        self.assertEqual(len(generate_session_key()), 32)
        self.assertNotEqual(generate_session_key(), generate_session_key())


if __name__ == "__main__":
    unittest.main(verbosity=2)

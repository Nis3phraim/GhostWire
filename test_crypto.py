"""Test that GhostWire crypto works correctly"""

import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from shared.crypto import AESCipher, RSAKeyManager, generate_session_key
from shared.config import RSA_PUB_FILE, RSA_PRIV_FILE

print("=" * 55)
print("  GhostWire Crypto Test")
print("=" * 55)

# ─── Test 1: AES Encryption ───
print("\n[TEST 1] AES-256 Encryption/Decryption")
print("-" * 40)

aes_key = generate_session_key()
aes = AESCipher(aes_key)

plaintext = "whoami"
print(f"  Original:   {plaintext}")

encrypted = aes.encrypt(plaintext)
print(f"  Encrypted:  {encrypted}")

decrypted = aes.decrypt(encrypted)
print(f"  Decrypted:  {decrypted}")

assert decrypted == plaintext, "AES decryption failed!"
print("  ✅ AES encryption/decryption works!")

# ─── Test 2: AES with longer text ───
print("\n[TEST 2] AES with longer text")
print("-" * 40)

long_text = "nisanephraimberg"
encrypted2 = aes.encrypt(long_text)
decrypted2 = aes.decrypt(encrypted2)

print(f"  Original:   {long_text}")
print(f"  Encrypted:  {encrypted2}")
print(f"  Decrypted:  {decrypted2}")

assert decrypted2 == long_text, "AES long text failed!"
print("  ✅ AES works with longer text!")

# ─── Test 3: Different encryptions produce different output ───
print("\n[TEST 3] Same input, different ciphertext (random IV)")
print("-" * 40)

enc1 = aes.encrypt("hello")
enc2 = aes.encrypt("hello")

print(f"  First:  {enc1}")
print(f"  Second: {enc2}")

assert enc1 != enc2, "Same input should produce different ciphertext!"
print("  ✅ Random IV works — same plaintext, different ciphertext!")
print("  💡 This means blue team can't detect repeated messages!")

# ─── Test 4: RSA Key Exchange ───
print("\n[TEST 4] RSA Key Exchange")
print("-" * 40)

print("  Loading keys...")
private_key = RSAKeyManager.load_private_key(RSA_PRIV_FILE)
public_key = RSAKeyManager.load_public_key(RSA_PUB_FILE)

new_aes_key = generate_session_key()
print(f"  New AES key: {new_aes_key.hex()[:16]}...")

encrypted_key = RSAKeyManager.encrypt_key(new_aes_key, public_key)
print(f"  Encrypted key: {encrypted_key[:32]}...")

decrypted_key = RSAKeyManager.decrypt_key(encrypted_key, private_key)
print(f"  Decrypted key: {decrypted_key.hex()[:16]}...")

assert decrypted_key == new_aes_key, "RSA key exchange failed!"
print("  ✅ RSA key exchange works!")

# ─── Test 5: Full flow — simulate implant and server ───
print("\n[TEST 5] Full Flow — Implant ↔ Server")
print("-" * 40)

print("\n  ─── SETUP ───")
print("  Server generates RSA key pair ✅ (already done)")
print("  Implant has RSA public key ✅ (embedded when generated)")

print("\n  ─── REGISTRATION ───")
implant_aes_key = generate_session_key()
print(f"  1. Implant generates AES key: {implant_aes_key.hex()[:16]}...")

encrypted_aes_key = RSAKeyManager.encrypt_key(implant_aes_key, public_key)
print(f"  2. Implant encrypts AES key with RSA public key")
print(f"     Encrypted: {encrypted_aes_key[:32]}...")

server_aes_key = RSAKeyManager.decrypt_key(encrypted_aes_key, private_key)
print(f"  3. Server decrypts AES key with RSA private key")
print(f"     Decrypted: {server_aes_key.hex()[:16]}...")

assert server_aes_key == implant_aes_key, "Keys don't match!"
print("  ✅ Both sides now have the same AES key!")

print("\n  ─── COMMUNICATION ───")
implant_aes = AESCipher(implant_aes_key)
server_aes = AESCipher(server_aes_key)

# Implant sends data
data_from_implant = implant_aes.encrypt("whoami")
print(f"\n  4. Implant encrypts 'whoami': {data_from_implant[:32]}...")

# Server decrypts
decrypted_by_server = server_aes.decrypt(data_from_implant)
print(f"  5. Server decrypts: {decrypted_by_server}")

# Server sends command
cmd_from_server = server_aes.encrypt("CMD:whoami")
print(f"\n  6. Server encrypts 'CMD:whoami': {cmd_from_server[:32]}...")

# Implant decrypts
decrypted_by_implant = implant_aes.decrypt(cmd_from_server)
print(f"  7. Implant decrypts: {decrypted_by_implant}")

assert decrypted_by_server == "whoami"
assert decrypted_by_implant == "CMD:whoami"
print("\n  ✅ Full encrypted communication works!")

print("\n" + "=" * 55)
print("  🎉 ALL CRYPTO TESTS PASSED!")
print("=" * 55)

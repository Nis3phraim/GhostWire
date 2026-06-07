"""
GhostWire Key Generator
=======================
Generates RSA-2048 key pair for C2 encryption.
It creates:
  - keys/rsa_priv.pem  (PRIVATE key — stays on server, NEVER share)
  - keys/rsa_pub.pem   (PUBLIC key — gets embedded in implant)
  """
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared.crypto import RSAKeyManager
from shared.config import RSA_PUB_FILE, RSA_PRIV_FILE


def main():
    print("=" * 55)
    print("  GhostWire RSA Key Generator")
    print("=" * 55)

    print("\n  Generating RSA-2048 key pair...")
    print("  (This may take a few seconds)\n")

    private_key, public_key = RSAKeyManager.generate_keys()

    print(f"  Saving private key to: {RSA_PRIV_FILE}")
    RSAKeyManager.save_private_key(private_key, RSA_PRIV_FILE)

    print(f"  Saving public key to:   {RSA_PUB_FILE}")
    RSAKeyManager.save_public_key(public_key, RSA_PUB_FILE)

    print("\n  ✅ Keys generated successfully!")
    print("\n  ⚠️  IMPORTANT:")
    print("  ─────────────────────────────────────────────")
    print("  • rsa_priv.pem → Keep on SERVER only. NEVER share!")
    print("  • rsa_pub.pem  → Embed in the IMPLANT. Safe to share.")
    print("  ─────────────────────────────────────────────\n")


if __name__ == "__main__":
    main()

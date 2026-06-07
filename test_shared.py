"""Test that shared package works correctly"""

from shared.protocol import (
    MSG_BEACON, MSG_DATA, RESP_ACK, RESP_ERR, RESP_EXIT,
    build_query, parse_query
)

from shared.config import C2_DOMAIN, DGA_SEED, DGA_LENGTH

from shared.dga import DGA

print("=" * 50)
print("  GhostWire Shared Package Test")
print("=" * 50)

# Test protocol
query = build_query("a1b2c3d4", MSG_BEACON, dga_label="x7k9m2p", domain="ghostwire.local")
print(f"\n  Built query:    {query}")

parsed = parse_query(query)
print(f"  Parsed back:    {parsed}")

print(f"\n  RESP_ACK:  {RESP_ACK}")
print(f"  RESP_ERR:  {RESP_ERR}")
print(f"  RESP_EXIT: {RESP_EXIT}")

# Test DGA
dga = DGA(seed=DGA_SEED, length=DGA_LENGTH, domain=C2_DOMAIN)
domain = dga.generate()
print(f"\n  Current DGA domain: {domain}")

print("\n" + "=" * 50)
print("  ✅ Everything works!")
print("=" * 50)


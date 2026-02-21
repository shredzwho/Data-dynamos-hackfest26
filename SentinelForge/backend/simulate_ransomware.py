import os
import time

filepath = os.path.join(os.getcwd(), "SentinelForge-Vault", "crypto_wallet.dat")

if os.path.exists(filepath):
    print(f"Bait file found at {filepath}")
    print("Simulating Ransomware Encryption sweep...")
    with open(filepath, "a") as f:
        f.write("\n[ENCRYPTED_BY_RYUK_RANSOMWARE_SIMULATION]")
    print("Success. Check SentinelForge Dashboard for Integrity Alert.")
else:
    print(f"Failed. Bait file NOT FOUND at {filepath}")

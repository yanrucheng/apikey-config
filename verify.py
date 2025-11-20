#!/usr/bin/env python3
"""Example script showing how to verify API keys using public keys"""

import sys
import json
import os
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# This would normally be fetched from GitHub Pages
# Example of what a service would do
def fetch_public_keys_from_github_pages():
    """Simulate fetching public keys from GitHub Pages"""
    # In real scenario, this would use requests.get()
    # Try JSON first (industry recommended)
    if os.path.exists("public-keys.json"):
        with open("public-keys.json", "r") as f:
            return json.load(f)
    # Fallback to text format
    elif os.path.exists("public-keys.txt"):
        with open("public-keys.txt", "r") as f:
            keys = {}
            for line in f:
                line = line.strip()
                if line and "|" in line:
                    name, public_key = line.split("|", 1)
                    keys[name] = public_key
            return keys
    # No public keys file found
    return {}


def verify_api_key(secret_key):
    """Verify if a secret key is valid by deriving and comparing public keys"""
    ph = PasswordHasher()
    public_keys = fetch_public_keys_from_github_pages()

    for name, stored_public_key in public_keys.items():
        try:
            # This will raise VerifyMismatchError if secret doesn't match
            ph.verify(stored_public_key, secret_key)
            print(f"✓ Secret key is valid for '{name}'")
            return True, name
        except VerifyMismatchError:
            continue  # Try next key

    print("✗ Invalid secret key")
    return False, None


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <secret_key>")
        return 1

    secret_key = sys.argv[1]
    verify_api_key(secret_key)
    return 0


if __name__ == "__main__":
    sys.exit(main())

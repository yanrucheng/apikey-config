#!/usr/bin/env python3
"""Secure API key manager with public key verification using Argon2id"""

import argparse
import os
import sys
import secrets
import json
from argon2 import PasswordHasher

# Constants
DATA_FILE = ".apikeys.json"
PH = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)


def generate_secret_key(length=32):
    """Generate a cryptographically secure secret key"""
    return secrets.token_urlsafe(length)


def derive_public_key(secret_key):
    """Derive a public key from secret key using Argon2id (one-way)"""
    return PH.hash(secret_key)


def load_keys():
    """Load all keys from JSON storage"""
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}


def save_keys(keys):
    """Save all keys to JSON storage"""
    with open(DATA_FILE, "w") as f:
        json.dump(keys, f, indent=2, sort_keys=True)


def create_key(name):
    """Create a new API key pair"""
    keys = load_keys()

    if name in keys:
        print(f"Error: Key '{name}' already exists")
        return 1

    # Generate secret key (never stored)
    secret_key = generate_secret_key()

    # Derive public key
    public_key = derive_public_key(secret_key)

    # Save only the public key
    keys[name] = public_key
    save_keys(keys)

    # Show secret key once
    print(f"✓ Created API key '{name}'")
    print(f"   Secret key: {secret_key}")
    print(f"   (⚠️  This secret will never be shown again - store it securely!)")
    return 0


def list_keys():
    """List all stored public keys"""
    keys = load_keys()

    if not keys:
        print("No API keys stored")
        return 0

    print("Stored API keys:")
    print("-" * 60)
    for name, public_key in sorted(keys.items()):
        print(f"{name:<20} {public_key[:40]}...")  # Show first 40 chars
    return 0


def delete_key(name):
    """Delete an API key"""
    keys = load_keys()

    if name not in keys:
        print(f"Error: Key '{name}' not found")
        return 1

    del keys[name]
    save_keys(keys)
    print(f"✓ Deleted API key '{name}'")
    return 0


def export_public_keys(output_file="public-keys.txt"):
    """Export public keys for GitHub Pages"""
    keys = load_keys()

    with open(output_file, "w") as f:
        for name, public_key in sorted(keys.items()):
            f.write(f"{name}|{public_key}\n")

    print(f"✓ Exported {len(keys)} public keys to '{output_file}'")
    return 0


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Secure API key manager")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Create command
    create_parser = subparsers.add_parser("create", help="Create a new API key")
    create_parser.add_argument("name", help="Name for the API key")

    # List command
    subparsers.add_parser("list", help="List all API keys")

    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete an API key")
    delete_parser.add_argument("name", help="Name of the API key to delete")

    # Export command (for GitHub Pages)
    export_parser = subparsers.add_parser("export", help="Export public keys for GitHub Pages")
    export_parser.add_argument("--output", default="public-keys.txt", help="Output file name")

    args = parser.parse_args()

    if args.command == "create":
        return create_key(args.name)
    elif args.command == "list":
        return list_keys()
    elif args.command == "delete":
        return delete_key(args.name)
    elif args.command == "export":
        return export_public_keys(args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())

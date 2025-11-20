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


def create_key(service, name):
    """Create a new API key pair for a service"""
    keys = load_keys()

    # Initialize service if it doesn't exist
    if service not in keys:
        keys[service] = {}

    # Check if key already exists for this service
    if name in keys[service]:
        print(f"Error: Key '{name}' already exists in service '{service}'")
        return 1

    # Generate secret key (never stored)
    secret_key = generate_secret_key()

    # Derive public key
    public_key = derive_public_key(secret_key)

    # Save only the public key under the service
    keys[service][name] = public_key
    save_keys(keys)

    # Show secret key once
    print(f"✓ Created API key '{name}' in service '{service}'")
    print(f"   Secret key: {secret_key}")
    print(f"   (⚠️  This secret will never be shown again - store it securely!)")
    return 0


def list_keys(filter_service=None):
    """List all stored public keys, optionally filtered by service"""
    keys = load_keys()

    # Check if there are any keys
    if not keys:
        print("No API keys stored")
        return 0

    # Prepare services to display
    display_services = []
    if filter_service:
        if filter_service in keys:
            display_services.append(filter_service)
        else:
            print(f"No API keys stored for service '{filter_service}'")
            return 0
    else:
        display_services = sorted(keys.keys())

    print("Stored API keys:")
    print("-" * 75)

    for service in display_services:
        service_keys = keys[service]
        print(f"Service: {service}")
        print("-" * 75)
        for name, public_key in sorted(service_keys.items()):
            print(f"{name:<20} {public_key[:40]}...")  # Show first 40 chars
        if len(display_services) > 1:  # Add blank line between services
            print()
    return 0


def delete_key(service, name):
    """Delete an API key from a service"""
    keys = load_keys()

    # Check if service exists
    if service not in keys:
        print(f"Error: Service '{service}' not found")
        return 1

    # Check if key exists in service
    if name not in keys[service]:
        print(f"Error: Key '{name}' not found in service '{service}'")
        return 1

    # Delete the key
    del keys[service][name]

    # Remove service if it has no more keys
    if not keys[service]:
        del keys[service]

    save_keys(keys)
    print(f"✓ Deleted API key '{name}' from service '{service}'")
    return 0


def export_public_keys(output_file="public-keys.json", format="json"):
    """Export public keys for GitHub Pages"""
    keys = load_keys()

    if format == "json":
        # Export the full service-based structure
        with open(output_file, "w") as f:
            json.dump(keys, f, indent=2, sort_keys=True)
    elif format == "text":
        # For text format, flatten by prefixing key names with service
        with open(output_file, "w") as f:
            for service in sorted(keys.keys()):
                for name, public_key in sorted(keys[service].items()):
                    f.write(f"{service}.{name}|{public_key}\n")
    else:
        print(f"Error: Unsupported format '{format}' - use 'json' or 'text'")
        return 1

    # Count total keys
    total_keys = sum(len(service_keys) for service_keys in keys.values())
    print(f"✓ Exported {total_keys} public keys to '{output_file}' in {format} format")
    return 0


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Secure API key manager")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Create command
    create_parser = subparsers.add_parser("create", help="Create a new API key")
    create_parser.add_argument("service", help="Service name for the API key")
    create_parser.add_argument("name", help="Name for the API key")

    # List command
    list_parser = subparsers.add_parser("list", help="List all API keys")
    list_parser.add_argument("--service", help="Service name to filter by")

    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete an API key")
    delete_parser.add_argument("service", help="Service name of the API key")
    delete_parser.add_argument("name", help="Name of the API key to delete")

    # Export command (for GitHub Pages)
    export_parser = subparsers.add_parser("export", help="Export public keys for GitHub Pages")
    export_parser.add_argument("--output", default="public-keys.json", help="Output file name")
    export_parser.add_argument("--format", choices=["json", "text"], default="json", help="Export format (default: json)")

    args = parser.parse_args()

    if args.command == "create":
        return create_key(args.service, args.name)
    elif args.command == "list":
        return list_keys(args.service)
    elif args.command == "delete":
        return delete_key(args.service, args.name)
    elif args.command == "export":
        return export_public_keys(args.output, args.format)

    return 0


if __name__ == "__main__":
    sys.exit(main())

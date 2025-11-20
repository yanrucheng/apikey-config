# API Key Config

A secure API key manager that uses one-way cryptography (Argon2id) to generate verifiable API keys without storing secrets.

## Features

- **Secure Generation**: Uses Argon2id (NIST-recommended) for one-way public key derivation
- **No Secret Storage**: Secrets are only shown once during creation - never stored
- **Public Key Export**: Export public keys for external services to verify requests
- **Simple CLI**: Easy-to-use commands for key management

## Installation

```bash
# Initialize virtual environment
uv venv

# Activate virtual environment
source .venv/bin/activate

# Install package
uv pip install -e .
```

## Usage

### Create an API Key

```bash
apikey create ai-album
```

Output:
```
✓ Created API key 'ai-album'
   Secret key: ld1X0w5kRu-pQot97ZT2FBQiawYYMWOcgZX4hR5TOf0
   (⚠️  This secret will never be shown again - store it securely!)
```

### List Keys

```bash
apikey list
```

Output:
```
Stored API keys:
----------------------------------------
ai-album             $argon2id$v=19$m=65536,t=3,p=4$rYIN6XsdD...
```

### Delete a Key

```bash
apikey delete ai-album
```

Output:
```
✓ Deleted API key 'ai-album'
```

### Export Public Keys (for GitHub Pages)

```bash
apikey export --output public-keys.txt
```

Output:
```
✓ Exported 2 public keys to 'public-keys.txt'
```

The `public-keys.txt` file can be published to GitHub Pages for external services to access.

## Verification Flow

1. **Service Setup**: External services fetch public keys from your GitHub Pages
2. **User Request**: User provides their secret key with a request
3. **Derive and Compare**: Service derives a public key from the secret and compares it against the fetched list
4. **Authentication**: If a match is found, the request is authenticated

## Security Details

- **Algorithm**: Argon2id (version 19) with:
  - Memory cost: 65536 KB
  - Time cost: 3 iterations
  - Parallelism: 4
  - Hash length: 32 bytes
  - Salt length: 16 bytes
- **Secret Handling**: Secrets are generated using `secrets.token_urlsafe()` and never stored
- **Public Exposure**: Only non-sensitive public keys are exposed

## Example Verification (for Service Developers)

Services can verify keys like this:

```python
from argon2 import PasswordHasher

ph = PasswordHasher()
stored_public_key = "$argon2id$v=19$m=65536,t=3,p=4$rYIN6XsdD..."

try:
    ph.verify(stored_public_key, user_provided_secret)
    # Authentication successful
except VerifyMismatchError:
    # Authentication failed
```

## Files

- `.apikeys`: Local storage of name-to-public-key mappings (never commit this!)
- `public-keys.txt`: Exported public keys (safe to commit/publish)

## License

MIT

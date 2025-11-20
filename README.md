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

API keys are now associated with services. Use:

```bash
uv run python apikey.py create <service> <name>
```

Example:
```bash
uv run python apikey.py create analytics api-key-1
```

Output:
```
✓ Created API key 'api-key-1' in service 'analytics'
   Secret key: ld1X0w5kRu-pQot97ZT2FBQiawYYMWOcgZX4hR5TOf0
   (⚠️  This secret will never be shown again - store it securely!)
```

### List Keys

```bash
uv run python apikey.py list
```

Output:
```
Stored API keys:
---------------------------------------------------------------------------
Service: analytics
---------------------------------------------------------------------------
api-key-1            $argon2id$v=19$m=65536,t=3,p=4$rYIN6XsdD...
api-key-2            $argon2id$v=19$m=65536,t=3,p=4$abcdef123...

Service: payment
---------------------------------------------------------------------------
stripe-key           $argon2id$v=19$m=65536,t=3,p=4$xyz456...
```

To list keys for a specific service:
```bash
uv run python apikey.py list --service analytics
```

Output:
```
Stored API keys:
---------------------------------------------------------------------------
Service: analytics
---------------------------------------------------------------------------
api-key-1            $argon2id$v=19$m=65536,t=3,p=4$rYIN6XsdD...
api-key-2            $argon2id$v=19$m=65536,t=3,p=4$abcdef123...
```

### Delete a Key

```bash
uv run python apikey.py delete <service> <name>
```

Example:
```bash
uv run python apikey.py delete analytics api-key-2
```

Output:
```
✓ Deleted API key 'api-key-2' from service 'analytics'
```

### Export Public Keys (for GitHub Pages)

**JSON format (industry recommended)**:
```bash
uv run python apikey.py export --output public-keys.json
```

This exports the keys in a service-based structure:
```json
{
  "analytics": {
    "api-key-1": "$argon2id$v=19$m=65536,t=3,p=4$rYIN6XsdD...",
    "api-key-2": "$argon2id$v=19$m=65536,t=3,p=4$abcdef123..."
  },
  "payment": {
    "stripe-key": "$argon2id$v=19$m=65536,t=3,p=4$xyz456..."
  }
}
```

**Text format (legacy)**:
```bash
uv run python apikey.py export --output public-keys.txt --format text
```

This exports in a flattened format with service names prefixed:
```
analytics.api-key-1|$argon2id$v=19$m=65536,t=3,p=4$rYIN6XsdD...
analytics.api-key-2|$argon2id$v=19$m=65536,t=3,p=4$abcdef123...
payment.stripe-key|$argon2id$v=19$m=65536,t=3,p=4$xyz456...
```

Output example:
```
✓ Exported 3 public keys to 'public-keys.json' in json format
```

The exported file (`public-keys.json` or `public-keys.txt`) can be published to GitHub Pages for external services to access.

### Deploy to GitHub Pages (Automated)

This repository includes a GitHub Actions workflow that automatically deploys public keys to GitHub Pages whenever changes are pushed to the main branch.

#### How it works:
1. Export your public keys locally:
   ```bash
   uv run python apikey.py export --output public-keys.json
   ```

2. Commit the exported public keys file:
   ```bash
   git add public-keys.json
   git commit -m "Update public keys"
   ```

3. Push to GitHub:
   ```bash
   git push origin main
   ```

4. GitHub Actions will automatically:
   - Checkout the latest code
   - Deploy the public-keys.json (and public-keys.txt if exists) to GitHub Pages
   - Make them available at: `https://apikeys.cyanru.com/keys/public-keys.json`

#### GitHub Pages Setup:
1. Go to your GitHub repository settings
2. Navigate to "Pages" section
3. Under "Build and deployment", select "GitHub Actions" as the source
4. The workflow will be automatically detected and run on pushes

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

### JSON Format (Recommended)
```python
import requests
import json
from argon2 import PasswordHasher

def verify_api_key(secret_key):
    # Fetch public keys from GitHub Pages
    response = requests.get("https://apikeys.cyanru.com/keys/public-keys.json")
    public_keys = response.json()

    ph = PasswordHasher()
    for name, stored_public_key in public_keys.items():
        try:
            ph.verify(stored_public_key, secret_key)
            return True, name
        except VerifyMismatchError:
            continue
    return False, None
```

### Text Format
```python
import requests
from argon2 import PasswordHasher

def verify_api_key(secret_key):
    # Fetch public keys from GitHub Pages
    response = requests.get("https://apikeys.cyanru.com/keys/public-keys.txt")

    ph = PasswordHasher()
    for line in response.text.splitlines():
        if line and "|" in line:
            name, stored_public_key = line.split("|", 1)
            try:
                ph.verify(stored_public_key, secret_key)
                return True, name
            except VerifyMismatchError:
                continue
    return False, None
```

## Files

- `.apikeys.json`: Local JSON storage of name-to-public-key mappings (never commit this!)
- `public-keys.json`: Exported public keys in JSON format (safe to commit/publish - industry recommended)
- `public-keys.txt`: Exported public keys in text format (safe to commit/publish - legacy support)

## License

MIT

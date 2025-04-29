# individual-task



## Overview

This project provides two command-line scripts for signing and verifying images (PNG or JPEG) using RSA-PSS signatures embedded directly into image metadata. It ensures authenticity and integrity without altering the visual appearance of the image.

## Features

- **RSA Key Generation**: 4096-bit RSA key pair generation via OpenSSL.
- **Image Signing**:
  - **PNG**: Embeds signature in a tEXt chunk named `Signature`.
  - **JPEG**: Inserts signature in a COM (comment) marker immediately after the SOI marker, preserving original bytes.
- **Signature Verification**: Verifies embedded signatures against raw pixel data (PNG) or original file bytes (JPEG).
- **Minimal Dependencies**: Pure Python with Pillow and cryptography; uses system OpenSSL CLI for key operations.

## Requirements

- **Python**: 3.8 or higher
- **OpenSSL**: CLI installed and in PATH
- **Python Packages**:
  - Pillow
  - cryptography

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/image-signature-utility.git
   cd image-signature-utility
   ```

2. **Generate RSA key pair**:
   ```bash
   openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:4096
   openssl rsa -pubout -in private_key.pem -out public_key.pem
   ```

3. **Install Python dependencies**:
   ```bash
   python3 -m pip install --user Pillow cryptography
   ```

## Usage

### Signing an image

```bash
python3 sign_image.py <input.png|jpg> <output.png|jpg> <private_key.pem>
```

**Example**:
```bash
$ python3 sign_image.py image.jpg signed_image.jpg private_key.pem
Signed image saved to: signed_image.jpg
```

### Verifying a signed image

```bash
python3 verify_image.py <signed.png|jpg> <public_key.pem>
```

**Example**:
```bash
$ python3 verify_image.py signed_image.jpg public_key.pem
Signature valid
```


## Detailed Approach

1. **Key Generation**
   - Use OpenSSL CLI to create a 4096-bit RSA private key and extract the public key in PEM format.

2. **Signing Process**:
   - **PNG**:
     1. Open image with Pillow and extract raw pixel bytes.
     2. Compute SHA-256 digest over pixel data.
     3. Sign digest using RSA-PSS (cryptography library).
     4. Encode signature in Base64 and embed it in a tEXt chunk named `Signature`.
   - **JPEG**:
     1. Read entire JPEG file as raw bytes.
     2. Compute SHA-256 digest over file bytes.
     3. Sign digest with RSA-PSS.
     4. Base64-encode signature and construct a COM marker.
     5. Insert COM marker immediately after the SOI (start-of-image) marker without re-saving image data.

3. **Verification Process**:
   - Extract Base64 signature from metadata (PNG tEXt chunk or JPEG COM marker).
   - Decode signature and recompute the same digest (pixel bytes for PNG, reconstructed raw bytes for JPEG).
   - Use RSA-PSS verification with the public key to confirm authenticity.

## Notes

- Embedding occurs only in metadata; the image binary content remains unchanged for viewing.




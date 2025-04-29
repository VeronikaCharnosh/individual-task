import sys
import base64
from pathlib import Path

from PIL import Image
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def compute_png_digest(image: Image.Image) -> bytes:
    """Compute SHA-256 digest of raw PNG pixel data."""
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(image.tobytes())
    return hasher.finalize()


def compute_file_digest(data: bytes) -> bytes:
    """Compute SHA-256 digest of raw bytes (for JPEG)."""
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(data)
    return hasher.finalize()


def verify_image(signed_path: str, public_key_path: str) -> None:
    """
    Verify the embedded signature in a signed image.

    - PNG: read from tEXt chunk.
    - JPEG: parse COM marker, strip it, then verify.
    """
    ext = Path(signed_path).suffix.lower()
    public_key = serialization.load_pem_public_key(Path(public_key_path).read_bytes())

    if ext == '.png':
        image = Image.open(signed_path)
        info = image.info
        if 'Signature' not in info:
            print('ERROR: No Signature chunk found.')
            sys.exit(1)
        signature = base64.b64decode(info['Signature'])
        digest = compute_png_digest(image)

    elif ext in ('.jpg', '.jpeg'):
        data = Path(signed_path).read_bytes()
        if data[2:4] != b'\xFF\xFE':
            print('ERROR: No COM marker found.')
            sys.exit(1)
        length = int.from_bytes(data[4:6], 'big')
        comment_bytes = data[6:6 + length - 2]
        signature = base64.b64decode(comment_bytes)
        original = data[:2] + data[6 + length - 2:]
        digest = compute_file_digest(original)

    else:
        raise ValueError(f'Unsupported format: {ext}')

    try:
        public_key.verify(
            signature,
            digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print('Signature valid')
    except Exception as err:
        print('Signature invalid', err)
        sys.exit(1)




def main() -> None:
    """Entry point for CLI."""
    if len(sys.argv) != 3:
        print('Usage: python3 verify_image.py output.jpg public_key.pem')
        sys.exit(1)
    signed_file, pub_file = sys.argv[1:]
    verify_image(signed_file, pub_file)


if __name__ == '__main__':
    main()

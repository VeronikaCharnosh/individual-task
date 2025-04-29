import sys
import base64
from pathlib import Path

from PIL import Image, PngImagePlugin
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


def sign_image(input_path: str, output_path: str, private_key_path: str) -> None:
    """
    Sign the image and embed the signature.

    - PNG: use raw pixel digest and embed in tEXt chunk.
    - JPEG: use file byte digest, insert COM marker before data.
    """
    ext = Path(input_path).suffix.lower()
    key_bytes = Path(private_key_path).read_bytes()
    private_key = serialization.load_pem_private_key(key_bytes, password=None)

    if ext == '.png':
        image = Image.open(input_path)
        digest = compute_png_digest(image)
        signature = private_key.sign(
            digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        b64sig = base64.b64encode(signature).decode('ascii')
        png_info = PngImagePlugin.PngInfo()
        png_info.add_text('Signature', b64sig)
        image.save(output_path, format='PNG', pnginfo=png_info)

    elif ext in ('.jpg', '.jpeg'):
        data = Path(input_path).read_bytes()
        digest = compute_file_digest(data)
        signature = private_key.sign(
            digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        b64sig = base64.b64encode(signature).decode('ascii')
        comment_bytes = b64sig.encode('ascii')
        length = len(comment_bytes) + 2
        com_marker = b'\xFF\xFE' + length.to_bytes(2, 'big') + comment_bytes
        signed_data = data[:2] + com_marker + data[2:]
        Path(output_path).write_bytes(signed_data)

    else:
        raise ValueError(f'Unsupported format: {ext}')

    print(f'Signed image saved to: {output_path}')


def main() -> None:
    """Command-line entry point for signing."""
    if len(sys.argv) != 4:
        print('Usage: python3 sign_image.py image.jpg output.jpg private_key.pem')
        sys.exit(1)
    sign_image(sys.argv[1], sys.argv[2], sys.argv[3])


if __name__ == '__main__':
    main()
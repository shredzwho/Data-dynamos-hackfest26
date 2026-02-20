import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_session_key() -> str:
    """Generate a 256-bit (32 byte) AES symmetric key base64 encoded."""
    key = os.urandom(32)
    return base64.b64encode(key).decode('utf-8')

def decrypt_message(session_key_b64: str, iv_b64: str, ciphertext_b64: str) -> str:
    """Decrypt an AES-GCM encrypted message."""
    try:
        key = base64.b64decode(session_key_b64)
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        # The authentication tag is typically the last 16 bytes of the ciphertext in WebCrypto AES-GCM
        if len(ciphertext) < 16:
            raise ValueError("Ciphertext too short to contain auth tag.")
        
        actual_ciphertext = ciphertext[:-16]
        auth_tag = ciphertext[-16:]

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, auth_tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')
    except Exception as e:
        # Re-raise or log
        raise ValueError(f"Failed to decrypt message: {str(e)}")

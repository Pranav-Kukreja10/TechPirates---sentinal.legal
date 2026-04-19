import base64
import secrets
from fastapi import HTTPException
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from audit import audit, logger

class E2EEncryption:
    def __init__(self):
        self._private_key = X25519PrivateKey.generate()
        self._public_key  = self._private_key.public_key()
        self._sessions: dict[str, bytes] = {}
        logger.info("E2E Encryption ready (cloud-only mode in v4.1).")

    @property
    def server_public_key_b64(self) -> str:
        raw = self._public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return base64.b64encode(raw).decode()

    def derive_session_key(self, client_pub_b64: str, session_id: str) -> str:
        raw = base64.b64decode(client_pub_b64)
        shared = self._private_key.exchange(X25519PublicKey.from_public_bytes(raw))
        key = HKDF(algorithm=hashes.SHA256(), length=32,
                   salt=session_id.encode(), info=b"SentinalLegal-v4").derive(shared)
        self._sessions[session_id] = key
        audit.log("HANDSHAKE", session_prefix=session_id[:8])
        return self.server_public_key_b64

    def encrypt(self, plaintext: str, sid: str) -> dict:
        key = self._sessions.get(sid)
        if not key:
            raise HTTPException(401, "No session key.")
        nonce = secrets.token_bytes(12)
        ct = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
        return {"ciphertext": base64.b64encode(ct).decode(), "nonce": base64.b64encode(nonce).decode()}

    def decrypt(self, ct_b64: str, nonce_b64: str, sid: str) -> str:
        key = self._sessions.get(sid)
        if not key:
            raise HTTPException(401, "No session key.")
        try:
            return AESGCM(key).decrypt(base64.b64decode(nonce_b64), base64.b64decode(ct_b64), None).decode()
        except Exception:
            raise HTTPException(400, "Decryption failed — data tampered or invalid nonce.")

    def invalidate(self, sid: str):
        self._sessions.pop(sid, None)

e2e = E2EEncryption()

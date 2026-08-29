"""Ed25519 signing for capabilities.

WHY CRYPTOGRAPHY AT ALL?
------------------------
A capability is a permission slip: "you may call issue_refund with amount<=50."
If the agent (or an injection) could fabricate or edit that slip, the whole
scheme is worthless. A signature solves two things at once:

  * INTEGRITY  — if a single byte of the capability is changed, the signature
                 no longer verifies. You cannot bump `amount` from 50 to 999.
  * AUTHENTICITY — only the holder of the private key (the Supervisor) can
                 produce a valid signature. The agent only ever sees the public
                 key, so it can VERIFY capabilities but never MINT them.

Ed25519 is asymmetric: sign with the private key, verify with the public key.
That separation is the point — the untrusted side can check but not forge.
(A symmetric HMAC would be simpler but would hand the verifier the same secret
used to sign, which we deliberately avoid.)
"""

from __future__ import annotations

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


class Signer:
    """Holds the PRIVATE key. Lives only inside the Supervisor."""

    def __init__(self, signing_key: SigningKey | None = None) -> None:
        self._sk = signing_key or SigningKey.generate()

    def sign(self, message: bytes) -> str:
        """Return a detached signature (hex) over the message."""
        return self._sk.sign(message).signature.hex()

    @property
    def verify_key_hex(self) -> str:
        """The PUBLIC key, safe to hand to the untrusted side."""
        return bytes(self._sk.verify_key).hex()

    def verifier(self) -> Verifier:
        return Verifier(self.verify_key_hex)


class Verifier:
    """Holds only the PUBLIC key. Safe to give to the agent side / the gate."""

    def __init__(self, verify_key_hex: str) -> None:
        self._vk = VerifyKey(bytes.fromhex(verify_key_hex))

    def verify(self, message: bytes, signature_hex: str) -> bool:
        try:
            self._vk.verify(message, bytes.fromhex(signature_hex))
            return True
        except (BadSignatureError, ValueError):
            return False

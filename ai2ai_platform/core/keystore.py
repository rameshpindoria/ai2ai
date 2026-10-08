"""Private keys encrypted at rest (Fernet / AES-128-CBC + HMAC) with a master key kept outside the code folder."""
import os

from cryptography.fernet import Fernet

from .crypto import Signer


class KeyStore:
    def __init__(self, data_dir: str, master_key: str = None):
        self.dir = os.path.join(data_dir, "keys")
        os.makedirs(self.dir, exist_ok=True)
        mk = master_key or os.environ.get("AI2AI_MASTER_KEY")
        if not mk:
            path = os.path.join(data_dir, "master.key")
            if not os.path.exists(path):
                with open(path, "wb") as fh:
                    fh.write(Fernet.generate_key())
            with open(path, "rb") as fh:
                mk = fh.read().strip()
        self._f = Fernet(mk if isinstance(mk, bytes) else mk.encode())

    def load_or_create(self, name: str, label: str) -> Signer:
        path = os.path.join(self.dir, f"{name}.key")
        if os.path.exists(path):
            with open(path, "rb") as fh:
                return Signer.from_private_bytes(label, self._f.decrypt(fh.read()))
        s = Signer(label)
        with open(path, "wb") as fh:
            fh.write(self._f.encrypt(s.private_bytes()))
        return s

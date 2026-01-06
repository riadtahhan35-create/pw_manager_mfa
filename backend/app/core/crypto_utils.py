import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type


# توليد DEK عشوائي (32 بايت)
def generate_dek() -> bytes:
    return os.urandom(32)


# اشتقاق KEK بواسطة Argon2id
def derive_kek(password: str, salt: bytes) -> bytes:
    """
    نشتق KEK من كلمة المرور + salt (هنا salt = SHA256(srp_salt))
    """
    kek = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )
    return kek


# تغليف DEK باستخدام KEK (AES-GCM)
def wrap_dek(kek: bytes, dek: bytes) -> str:
    """
    يأخذ KEK و DEK, يرجّع نص Base64 يحتوي nonce + ciphertext
    """
    aesgcm = AESGCM(kek)
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, dek, None)
    return base64.b64encode(nonce + encrypted).decode("utf-8")


# فك تغليف DEK باستخدام KEK
def unwrap_dek(kek: bytes, dek_wrapped_b64: str) -> bytes:
    """
    يأخذ KEK و النص المغلف Base64 ويرجّع DEK الأصلي (bytes)
    """
    data = base64.b64decode(dek_wrapped_b64)
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(kek)
    dek = aesgcm.decrypt(nonce, ciphertext, None)
    return dek


# تشفير بيانات (مثل face embedding) باستخدام DEK
def encrypt_with_dek(dek: bytes, plaintext: bytes) -> str:
    """
    تشفير أي بيانات (bytes) باستخدام AES-GCM بمفتاح DEK.
    يرجّع Base64(nonce + ciphertext)
    """
    aesgcm = AESGCM(dek)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


# فك تشفير بيانات باستخدام DEK
def decrypt_with_dek(dek: bytes, ciphertext_b64: str) -> bytes:
    """
    يفك Base64(nonce + ciphertext) ويرجّع plaintext (bytes)
    """
    data = base64.b64decode(ciphertext_b64)
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(dek)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext
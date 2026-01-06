import base64
import srp


def create_srp_verifier(username: str, password: str):
    """
    إنشاء salt و verifier باستخدام pysrp بشكل صحيح.
    هذه الدالة تُستخدم في مرحلة التسجيل فقط.
    """

    # ⚠️ مهم جداً: توحيد الهاش على SHA1 ليتطابق مع باقي مكتبة srp
    salt, vkey = srp.create_salted_verification_key(
        username,
        password,
        hash_alg=srp.SHA1,   # ← بدّلها من SHA256 إلى SHA1
        ng_type=srp.NG_2048,
    )

    return {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "verifier": base64.b64encode(vkey).decode("utf-8"),
    }
import base64
import requests
import srp

BASE_URL = "http://127.0.0.1:8000"

username = "riad"
password = "Rr@123456"


print("\n=== STEP 1: Client → Server (A) ===")

usr = srp.User(username, password, hash_alg=srp.SHA256, ng_type=srp.NG_2048)
uname, A = usr.start_authentication()

A_b64 = base64.b64encode(A).decode()
print(f"A (Base64): {A_b64}")

# 🚨 استدعاء المسار الصحيح وليس /auth/auth/login_start !
res1 = requests.post(
    f"{BASE_URL}/auth/login_start",
    params={
        "username": username,
        "A_b64": A_b64
    }
)

print("\nServer Response (STEP 1):")
print("Status:", res1.status_code)
print("Raw text:", res1.text)

# إذا ليس JSON → اطبع رسالة
try:
    data = res1.json()
    print("JSON:", data)
except:
    print("JSON: NOT PARSEABLE")
    raise SystemExit("❌ Server did NOT return JSON. Check server errors.")


# لو السيرفر أعطى JSON فعلاً نكمل
salt_b64 = data["salt"]
B_b64 = data["B"]
session_id = data["session_id"]


print("\n=== STEP 2: Client processes challenge (salt + B) ===")

salt = base64.b64decode(salt_b64)
B = base64.b64decode(B_b64)

M = usr.process_challenge(salt, B)
if M is None:
    print("❌ ERROR: process_challenge returned None")
    exit(1)

M_b64 = base64.b64encode(M).decode()


print("\n=== STEP 3: Client → Server (M) ===")

res2 = requests.post(
    f"{BASE_URL}/auth/login_verify",
    params={
        "username": username,
        "session_id": session_id,
        "M_b64": M_b64
    }
)

print("\nServer Response (STEP 2):")
print("Status:", res2.status_code)
print("Raw text:", res2.text)

try:
    data2 = res2.json()
    print("JSON:", data2)
except:
    print("JSON: NOT PARSEABLE")
    raise SystemExit("❌ Server did NOT return JSON. Check server errors.")


print("\n=== STEP 4: Client verifies HAMK ===")
HAMK_b64 = data2["server_proof"]

HAMK = base64.b64decode(HAMK_b64)

usr.verify_session(HAMK)

print("\nIs authenticated?:", usr.authenticated())
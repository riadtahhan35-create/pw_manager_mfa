from fastapi import APIRouter
router = APIRouter(
    prefix="/mfa",
    tags=["MFA"]
)
# هذا الملف محجوز فقط لأي MFA مستقبلي
# (OTP – Email – SMS – TOTP)
# لا يوجد هنا أي منطق متعلق بالوجه
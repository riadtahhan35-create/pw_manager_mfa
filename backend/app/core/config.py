import os

class Settings:
    # لاحقاً سنستبدل هذا ببيئة حقيقية عبر Docker
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "mysql+pymysql://pw_user:pw_pass123@localhost:3306/pw_manager_mfa"
    )

    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-key-for-testing")

settings = Settings()
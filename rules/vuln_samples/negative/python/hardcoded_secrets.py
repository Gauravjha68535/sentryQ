# NEGATIVE: Secrets from environment
import os

password = os.getenv("DB_PASSWORD")
api_key = os.environ.get("API_KEY")
jwt_secret = os.environ["JWT_SECRET"]

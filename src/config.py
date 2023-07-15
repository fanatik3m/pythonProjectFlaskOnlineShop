import os

from dotenv import load_dotenv

load_dotenv()

DB_URL = os.environ.get('DB_URL')
SECRET_KEY = os.environ.get('SECRET_KEY')
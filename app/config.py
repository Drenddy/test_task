import os
from dotenv import load_dotenv

load_dotenv()

PRIVATE_KEY = os.getenv('PRIVATE_KEY')
SECRET_KEY = os.getenv('SECRET_KEY')
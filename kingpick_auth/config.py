import os

JWT_PRIVATE_KEY = os.environ.get('JWT_PRIVATE_KEY', 'SET ME UP').replace('\\n', '\n')


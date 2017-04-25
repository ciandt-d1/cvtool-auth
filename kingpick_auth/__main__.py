#!/usr/bin/env python3
import os
import connexion
from .encoder import JSONEncoder

HOST = os.getenv('HOST', '0.0.0.0')
PORT = os.getenv('PORT', 8080)
DEBUG = os.getenv('DEBUG', False)

if __name__ == '__main__':
    app = connexion.App(__name__, specification_dir='./swagger/')
    app.app.json_encoder = JSONEncoder
    app.add_api('swagger.yaml', arguments={'title': 'Auth token provider'})
    app.run(port=PORT, debug=DEBUG, host=HOST)

#!/usr/bin/env python3

import connexion
from kingpick_auth.encoder import JSONEncoder

app = connexion.App(__name__, specification_dir='./kingpick_auth/swagger/')
app.app.json_encoder = JSONEncoder
app.add_api('swagger.yaml', arguments={'title': 'Provides APIs for tenant maintenance'})

def main():
    import os
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = os.getenv('PORT', 8080)
    DEBUG = os.getenv('DEBUG', False)
    app.run(port=PORT, debug=DEBUG, host=HOST)

if  __name__ =='__main__':
    main()
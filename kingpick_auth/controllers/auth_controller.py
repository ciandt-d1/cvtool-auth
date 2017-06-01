import base64
import json

import connexion
from oauth2client import crypt

from kingpick_auth.config import JWT_PRIVATE_KEY
from kingpick_auth.models.auth_info_response import AuthInfoResponse


def token():
    """
    token
    Generate a new authentication token

    :rtype: str
    """
    auth_info = _auth_info()

    payload = dict(
        sub=auth_info.get('id'),
        email=auth_info.get('email'),
        aud='cli',
        iss='cvtool'
    )

    signer = crypt.Signer.from_string(JWT_PRIVATE_KEY)
    jwt = crypt.make_signed_jwt(signer, payload, key_id='root')

    return jwt.decode('utf-8')


def _base64_decode(encoded_str):
    # Add paddings manually if necessary.
    num_missed_paddings = 4 - len(encoded_str) % 4
    if num_missed_paddings != 4:
        encoded_str += b'=' * num_missed_paddings
    return base64.b64decode(encoded_str).decode('utf-8')


def _auth_info():
    """Retrieves the authentication information from Google Cloud Endpoints."""
    encoded_info = connexion.request.headers.get('X-Endpoint-API-UserInfo', None)

    if encoded_info:
        info_json = _base64_decode(encoded_info)
        user_info = json.loads(info_json)
    else:
        user_info = {'id': 'anonymous'}

    return user_info


def tokeninfo():
    """Auth info with Google signed JWT."""
    return AuthInfoResponse.from_dict(_auth_info())



import connexion
from datetime import date, datetime
from typing import List, Dict
from six import iteritems
from ..util import deserialize_date, deserialize_datetime

from oauth2client import crypt

private_key_pkcs8_pem = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEApnYIVn0XlH9qgcz7Fhes8GTmxi0cZrt17IP/aWV8D+C//npc
vgCBEuGNnPHyEeMF+lTWJpPgQOVLpBFK7z2RYTU1bowQH0mYXM6iGOFT0vnxoV45
lD7gbYxVAWVQa9aPBqKeAVDOW97dx1lClWJn2l95rwUl1BcWgv4slV8v8MqF6eX3
TZoVWOEx6Go8kyA4maa6AYq1fQsxuYPJC+jIRYfPe7FWU7FVc2vq/dzDhxdKcToK
BTcb5Wrf6CpR7JQr7tefPKjOq4cqAN8PnWmKWdneIc6g8mVQD+UWHGsAsfTibsOh
qdK2eUb8LRvwb7fvXSIocvdjg88oFcF/yE+aTwIDAQABAoIBAET6Qig8u8mwJt1U
qHMWKnaPCUXzqYI0igARDoSJJiiaNFTqNYYSRWoihwETDQE2duKtxvPDcTjTC04Y
UFnkxFpopxSA+6lLYNSMV4VB0e9p3SPGHMv+ZhdfAFaMug+FoEzak+jtqCVPq80Q
gtPOLETELXNGCc/iJVTwqF7ZS89WIaBnEjIJ8dmd2mv3aLRUvnTyRcLSdDhoAnt/
HXIjP9VXtMXZyqBDFea3e0ndIGJmCCcQgrIzSt8KJS2gfMAYvgCpY76yEYCwUv7y
5l0dJg82KqA+H8mT1s4en6K3H2JEX7Y3FOGMYVj6SB2SctGS9nAOu18JJ5Sl+9aW
02kaJ5ECgYEA0TYyRmG0Zqhye3+DjFbiT5QOJ0R9YCtcZ20TOpX2LPCXnzkBWZqk
t0Byefvcqv+facK7uoxHlNch0mjDl5l4sgsa3mZ42NX78lNHBEBW8G+Mb4CoVXq0
RpanTSErc0w3ktvWjwcfmC3gpExN8209mv8peV0s+GaI0vrIO18dvzkCgYEAy7BG
AZWdFEjWEO+NoNzlc9BIBAIoLhYriMweRYsHUULJbMsWBFbOqhQeBrpys/ESQMRI
FytuASWY7D4WSVmWlmRcSU5EGAITt/aJ2EotQho5u2CnmaB5jrXjc56pbBux/8C2
nTEzPLYE1Tw/Vx51UIB/7J17jJJKxI+VsX86nccCgYBeALMQSsBrTA68jOwHt9ZS
GV1OqYiIGJOZaTo1ncISKTyHb2662zBdopiNVOyu7NKtC7GcPYHAT/XDfA0+ZdgE
b9bvzS1JiMR++oozT9GAkS6Rv0ZjuhGckf60Ok4yrTFfTGYYuAOrNhn02NBBq3j9
1t7EyGf3aOLboZEslC1iiQKBgQCvA6PzQpF4V2kPnjWsDYFd9I2cXBoYF1aKsRAl
ouLDsMYPo6QkUE48lxKBp3xdHnsXiU+EEP3xIFP4URSnK8IXMN6W4hfiJQ66V6xz
WrDuhkgqt07q0pb/x0tLEf3y9Q0JepWuFRM4TBF1AtJN0c7tP6wrK9l3nE9/+vud
SnucCwKBgE5xeL4rAU25qtAKPRHNQ9Zep0a66HlOcS5odDcw30mtYusHoD9TJQUW
qruUEtYkwmo2CKitCJk9fgqJic5253Gu4bhVMJG4EmZ3g5/i1lNg4I9beof6081M
QiL6oYLmNGSlr4xLD4q7k+nCPhjPl2MQ+pBrGDDh2wqsIulgecse
-----END RSA PRIVATE KEY-----"""

def token():
    """
    token
    Generate a new authentication token

    :rtype: str
    """
    __auth_info = _auth_info()

    payload = dict(
        sub=__auth_info.get('id'),
        email=__auth_info.get('email'),
        aud='cli',
        iss='kingpick.io'
    )        

    signer = crypt.Signer.from_string(private_key_pkcs8_pem)
    jwt = crypt.make_signed_jwt(signer, payload, key_id='frodo')

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


def auth_info():
    return jsonify(_user_info())
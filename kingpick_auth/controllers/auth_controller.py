import base64
import json

import connexion
from kingpick_auth.models.auth_info_response import AuthInfoResponse
from oauth2client import crypt


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

    signer = crypt.Signer.from_string("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEApofCICDb4Xt5K3+Qq05udbPni6hbAgjwmIBGmcmgcrfIBv6A\nUdj47NdGDQoc4XsTsyNU5w5kB9g8x4wm3gtCb5vukfovPVa81m2N98I2aC0mRKym\ny3sALrZyJ30HkuT9SggF+v2PNoeIUtcFM+WIsCNIvPvmmwdfqUEuHdBUWnAaMMH7\n8gq7V4+QRK5TvMJwC7n3JwPX6qf6fK0oT6FyZaW2+wrjZF5heCjRcYHLnBxk2vix\nKqO4MIXkw3E+fqcWyBrDeYbIIT79vjgMfSjHM9C4xzmuAfilrazjwVMtkAC0lYpT\nq4K5ktD+cjcpzKQ49vRnMh+uABYD/kSu0HKMGwIDAQABAoIBAFusDiw7im9U1j4g\nyhXTZjE7KPKTag3zt+ZrbvIHsWCVVPKstRzZUSan1vMkpwNlClIp1/odzOkYm1TK\nDTdcgWUJNMp9K/YbQnbT9jv2WJb+i7twQ51uB4qveqXMSRgPIHPZeNlTLbw53cyk\ne0O3ToiP0+Hc1XRwGbQFoopc/aKOggwZs4cbDzCro77rIJaR8x1bKyMlG9klgeCC\n+pMARBBClUVu4pMvy4y5tMDpJpQlG0IQ/fLysPF3sOK/7XkHSTnVSHzTOy236ka8\nF6gNe8Qg7h27GCfl1GMSbVDq0aSohlshl9hL9QIogoO1HqpKYEMDLSi+erVGzk63\nM/rOs3kCgYEAxoC9sj4uyjHMU5WL9BviBCVVxf/tMJYWMetRutfz7T81DI/PfYYH\nT//2wt2ylbt3iGpsV1fXRB6e6Vy0UmyoZq2i3oyJpX5SxMl2WpGd4MC2q3rCNLzJ\neqFQPdHppzNvXf2VJm93SVfkbMnvEK2Rs3cRJ3Qzm9wpE8x9z6a8Mc8CgYEA1sQ0\n2uh1Bw34n7fVtJq4fODck/8vsfrCxDtntcZzbq5CP1dTqnxV5jdSnBSCUME7hrSR\nbnOlDOpLnTMdy1R4pqhpapAMWyYXJVTKVcdClGjAPnunNXf6H8CUIrjLOYtzCdxQ\nLqW9ceAoBWIl5KE9Z8du0VRofq50r7lkBTuIT/UCgYB67G6MWoWPIJdvi0RHvpyQ\nBK7BFmNDmy3Ta+4IzoJ3gJTRWp0bFkyg9dlRgwh8QMMc7wp4bCUaQfwWdxoTkMYY\nD560QkNbAIcw5bEtFM+3xp9YQYTSM7ZxAkQ2hC81I1zrz4T1cEFmYc9KryIkKdf4\nUtuEmyj6c7PcVt3yIUaZcQKBgQC7x7ZHKTUZw/d8/ynVzeo9FgcHR/qV7aFaHm7h\nmvDW93ppE5vN1wTsU7bhTXVb0niPoVX/cxH/JuSSQF1uqR8M6Pey+twy3i0isO5w\n7dajGKvudgOPVqXWGXXsnhLi77DYEE/zWWs5JDsZ6eUj8G9WTCPy15C+Ix9Xfguc\nH59h+QKBgF2+ByYIekgNT4rFy7YnRHBg+7YudI09+eePxf0xPg+aebir18vY2lXj\nQulMjfZpysmkEerSHjuHY+HAp2oo5HvaNXYQ8qwEk3dldTXhNy6kYaC3xssaxdtz\nZJz0JVU4mS9NQQcG3l0jExMDVLmPDA4bTE5CQcNBjdjR/eRiOb8L\n-----END RSA PRIVATE KEY-----")
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



import base64
import json
import logging

import connexion
from googleapiclient import discovery
from oauth2client import crypt
from oauth2client.client import GoogleCredentials

from kingpick_auth.config import JWT_PRIVATE_KEY, GCP_PROJECT_ID, GCP_IAM_ALLOWED_ROLES
from kingpick_auth.models.auth_info_response import AuthInfoResponse

logger = logging.getLogger(__name__)

credentials = GoogleCredentials.get_application_default()
service = discovery.build('cloudresourcemanager', 'v1', credentials=credentials)


def token():
    """
    token
    Generate a new authentication token

    :rtype: str
    """
    auth_info = _auth_info()
    user_email = auth_info.get('email')
    user_id = auth_info.get('id')

    if _user_has_enough_privileges(user_email):
        payload = dict(
            sub=user_id,
            email=user_email,
            aud='cli',
            iss='cvtool'
        )
        signer = crypt.Signer.from_string(JWT_PRIVATE_KEY)
        jwt = crypt.make_signed_jwt(signer, payload, key_id='root')

        return jwt.decode('utf-8')
    else:
        return dict(message='Only project members are allowed'), 403


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


def _user_has_enough_privileges(user_email):
    get_iam_policy_request_body = {}
    request = service.projects().getIamPolicy(resource=GCP_PROJECT_ID, body=get_iam_policy_request_body)
    response = request.execute()
    bindings_members = [binding.get('members') for binding in response.get('bindings') if
                        binding.get('role') in GCP_IAM_ALLOWED_ROLES]
    allowed_members = [member[5:] for members in bindings_members for member in members if member.startswith('user:')]
    return user_email in allowed_members

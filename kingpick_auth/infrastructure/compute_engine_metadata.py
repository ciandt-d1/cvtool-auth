import logging
import os

import requests
from six.moves.urllib import parse as urlparse

_LOGGER = logging.getLogger(__name__)

_METADATA_ROOT = 'http://{}/computeMetadata/v1/'.format(
    os.getenv('GCE_METADATA_ROOT', 'metadata.google.internal'))

_METADATA_FLAVOR_HEADER = 'metadata-flavor'
_METADATA_FLAVOR_VALUE = 'Google'
_METADATA_HEADERS = {_METADATA_FLAVOR_HEADER: _METADATA_FLAVOR_VALUE}

try:
    _METADATA_DEFAULT_TIMEOUT = int(os.getenv('GCE_METADATA_TIMEOUT', 3))
except ValueError:  # pragma: NO COVER
    _METADATA_DEFAULT_TIMEOUT = 3


def get_project_id():
    base_url = urlparse.urljoin(_METADATA_ROOT, 'project/project-id')
    response = requests.get(base_url, headers=_METADATA_HEADERS, timeout=_METADATA_DEFAULT_TIMEOUT, allow_redirects=False)
    return response.text


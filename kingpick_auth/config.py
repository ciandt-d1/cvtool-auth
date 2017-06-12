import os
from .infrastructure.compute_engine_metadata import get_project_id

JWT_PRIVATE_KEY = os.environ.get('JWT_PRIVATE_KEY', 'SET ME UP').replace('\\n', '\n')

try:
    GCP_PROJECT_ID = os.environ['GOOGLE_CLOUD_PROJECT']
except KeyError:  # pragma: NO COVER
    GCP_PROJECT_ID = get_project_id()


GCP_IAM_ALLOWED_ROLES = ['roles/editor', 'roles/owner']



#!flask/bin/python

# Copyright 2019 Matthew Delotavo
# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

from flask import Flask, jsonify, request

os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = './google_application_credentials.json'

app = Flask(__name__)

@app.route('/')
def index():
    return 'OK'

def deidentify_with_mask(project, string, info_types, masking_character=None,
                         number_to_mask=0):
    """Uses the Data Loss Prevention API to deidentify sensitive data in a
    string by masking it with a character.
    """

    # Import the client library
    import google.cloud.dlp

    # Instantiate a client
    dlp = google.cloud.dlp.DlpServiceClient()

    # Convert the project id into a full resource id.
    parent = dlp.project_path(project)

    # Construct inspect configuration dictionary
    inspect_config = {
        'info_types': [{'name': info_type} for info_type in info_types]
    }

    # Construct deidentify configuration dictionary
    deidentify_config = {
        'info_type_transformations': {
            'transformations': [
                {
                    'primitive_transformation': {
                        'character_mask_config': {
                            'masking_character': masking_character,
                            'number_to_mask': number_to_mask
                        }
                    }
                }
            ]
        }
    }

    # Construct item
    item = {'value': string}

    # Call the API
    response = dlp.deidentify_content(
        parent, inspect_config=inspect_config,
        deidentify_config=deidentify_config, item=item)

    return response.item.value

def deidentify_with_fpe(project, string, info_types, alphabet=None,
                surrogate_type=None, key_name=None, wrapped_key=None):
    """Uses the Data Loss Prevention API to deidentify sensitive data in a
    string using Format Preserving Encryption (FPE).
    """
    # Import the client library
    import google.cloud.dlp

    # Instantiate a client
    dlp = google.cloud.dlp.DlpServiceClient()

    # Convert the project id into a full resource id.
    parent = dlp.project_path(project)

    # The wrapped key is base64-encoded, but the library expects a binary
    # string, so decode it here.
    import base64
    wrapped_key = base64.b64decode(wrapped_key)

    # Construct FPE configuration dictionary
    crypto_replace_ffx_fpe_config = {
        'crypto_key': {
            'kms_wrapped': {
                'wrapped_key': wrapped_key,
                'crypto_key_name': key_name
            }
        },
        'common_alphabet': alphabet
    }

    # Add surrogate type
    if surrogate_type:
        crypto_replace_ffx_fpe_config['surrogate_info_type'] = {
            'name': surrogate_type
        }

    # Construct inspect configuration dictionary
    inspect_config = {
        'info_types': [{'name': info_type} for info_type in info_types]
    }

    # Construct deidentify configuration dictionary
    deidentify_config = {
        'info_type_transformations': {
            'transformations': [
                {
                    'primitive_transformation': {
                        'crypto_replace_ffx_fpe_config':
                            crypto_replace_ffx_fpe_config
                    }
                }
            ]
        }
    }

    # Convert string to item
    item = {'value': string}

    # Call the API
    response = dlp.deidentify_content(
        parent, inspect_config=inspect_config,
        deidentify_config=deidentify_config, item=item)

    return response.item.value

def reidentify_with_fpe(project, string, alphabet=None,
                        surrogate_type=None, key_name=None, wrapped_key=None):
    """Uses the Data Loss Prevention API to reidentify sensitive data in a
    string that was encrypted by Format Preserving Encryption (FPE).
    """
    # Import the client library
    import google.cloud.dlp

    # Instantiate a client
    dlp = google.cloud.dlp.DlpServiceClient()

    # Convert the project id into a full resource id.
    parent = dlp.project_path(project)

    # The wrapped key is base64-encoded, but the library expects a binary
    # string, so decode it here.
    import base64
    wrapped_key = base64.b64decode(wrapped_key)

    # Construct Deidentify Config
    reidentify_config = {
        'info_type_transformations': {
            'transformations': [
                {
                    'primitive_transformation': {
                        'crypto_replace_ffx_fpe_config': {
                            'crypto_key': {
                                'kms_wrapped': {
                                    'wrapped_key': wrapped_key,
                                    'crypto_key_name': key_name
                                }
                            },
                            'common_alphabet': alphabet,
                            'surrogate_info_type': {
                                'name': surrogate_type
                            }
                        }
                    }
                }
            ]
        }
    }

    inspect_config = {
        'custom_info_types': [
            {
                'info_type': {
                    'name': surrogate_type
                },
                'surrogate_type': {
                }
            }
        ]
    }

    # Convert string to item
    item = {'value': string}

    # Call the API
    response = dlp.reidentify_content(
        parent,
        inspect_config=inspect_config,
        reidentify_config=reidentify_config,
        item=item)

    return response.item.value

@app.route('/clouddlp/v1/mask', methods=['POST'])
def mask_data():
    if not request.json or not 'message' in request.json:
        abort(400)

    project = request.json['project']
    message = request.json['message']

    info_types = [
        'ALL_BASIC'
    ]

    return deidentify_with_mask(project, message, info_types, '#')

@app.route('/clouddlp/v1/fpe', methods=['POST'])
def fpe_data():
    if not request.json or not 'message' in request.json:
        abort(400)

    info_types = [
        'FIRST_NAME',
        'LAST_NAME',
        'GENDER',
        'AUSTRALIA_MEDICARE_NUMBER',
        'AUSTRALIA_TAX_FILE_NUMBER',
        'PHONE_NUMBER'
    ]

    project = request.json['project']
    message = request.json['message']
    alphabet = request.json['alphabet']
    surrogate_type = request.json['surrogate_type']
    key_name = request.json['key_name']
    wrapped_key = request.json['wrapped_key']

    return deidentify_with_fpe(
        project, message, info_types,
        alphabet=alphabet, wrapped_key=wrapped_key, key_name=key_name, surrogate_type=surrogate_type)

@app.route('/clouddlp/v1/reid', methods=['POST'])
def reid_data():
    if not request.json or not 'message' in request.json:
        abort(400)

    project = request.json['project']
    message = request.json['message']
    alphabet = request.json['alphabet']
    surrogate_type = request.json['surrogate_type']
    key_name = request.json['key_name']
    wrapped_key = request.json['wrapped_key']

    return reidentify_with_fpe(project, message, alphabet, surrogate_type, key_name, wrapped_key)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)

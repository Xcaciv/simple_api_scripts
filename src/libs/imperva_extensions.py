import json
import requests
import os
import argparse
import pprint


# Function to get policy details
def get_policy(policy_id, base_url, api_id, api_key, caid=None, extended = True):
    url = f"{base_url}/v2/policies/{policy_id}?"
    if extended: url += 'extended=true'
    if extended and caid: url += '&'
    if caid: url += f'caid={caid}'

    headers = {
        'Accept': 'application/json',
        'x-API-Id': api_id,
        'x-API-Key': api_key,
        'Content-Type': 'application/json'
    }
    
    response = requests.get(url, headers=headers).json()
    if 'errMsg' in response:
        raise Exception(response['errMsg'])
    elif 'isError' in response and response['isError']: 
        raise Exception('Unable to find policy')
    
    return response['value']

def get_policy_exception_setting_id(policy):
    for setting in policy['policySettings']:
        if "policyDataExceptions" in setting:
            return setting['id']

def create_exception_update_object(policy_id, policy_settings_id, ip_addresses, comment, comment_max_len=120):   
    return {
        "id": policy_id, 
        "policySettings": [
              {
                "id": policy_settings_id, 
                "policyDataExceptions": [
                        {
                            "data": [
                                    {
                                        "exceptionType": "IP", 
                                        "values": ip_addresses
                                    }
                                ], 
                            "comment": comment[:comment_max_len]
                        }
                    ]
              }
            ]
        }

# Function to update policy with new IP exception
def add_ip_exception(policy_id, ip_address, reason, base_url, api_id, api_key, caid=None, reason_max_len=120):
# curl -X 'POST' \
#   'https://api.imperva.com/policies/v2/policies/1779750?caid=1769792' \
#   -H 'accept: application/json' \
#   -H 'x-API-Id: <id>' \
#   -H 'x-API-Key: <key>' \
#   -H 'Content-Type: application/json' \
#   -d '{
#     "policySettings": [
#       {
#         "id": 7310479,
#         "policyDataExceptions": [
#           {
#             "data": [
#               {
#                 "exceptionType": "IP",
#                 "values": [
#                   "64.223.136.47",
#                   "64.223.136.48",
#                   "64.223.136.49"
#                 ]
#               }
#             ],
#             "comment": "several test"
#           }
#         ]
#       }
#     ]
# }'

    policy = get_policy(policy_id, base_url, api_id, api_key, caid)
    print("Modifying policy: ", policy['description'])
    exceptionSettingsId = get_policy_exception_setting_id(policy)
    exceptionBody = create_exception_update_object(policy_id, exceptionSettingsId, [ip_address], reason, reason_max_len)
    
    url = f"{base_url}/v2/policies/{policy_id}?"
    if caid: url += f'caid={caid}'

    headers = {
        'Accept': 'application/json',
        'x-API-Id': api_id,
        'x-API-Key': api_key,
        'Content-Type': 'application/json'
    }
    try:
        response = requests.post(url, headers=headers, json=exceptionBody)
        if response.ok:
            return response.json() 
        else:
            response.raise_for_status()
        
    except Exception as e:
        raise Exception('Failed API call to Imperva') from e
        

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Add IP exception to a policy.')
    parser.add_argument('-p','--policy_id', type=int, required=True, help='The ID of the policy')
    parser.add_argument('-ip','--ip_address', type=str, required=True, help='The IP address to add as an exception')
    parser.add_argument('-c', '--comment', type=str, required=True, help='Reason for the exception')
    parser.add_argument('--api_id', type=str, default=os.getenv('IMPERVA_API_ID'), help='API ID for authentication')
    parser.add_argument('--api_key', type=str, default=os.getenv('IMPERVA_API_KEY'), help='API key for authentication')
    parser.add_argument('--base_url', type=str, default=os.getenv('IMPERVA_BASE_URL', 'https://api.imperva.com/policies'), help='Base URL for the API')
    parser.add_argument('--comment_max_len', type=int, default=os.getenv('IMPERVA_COMMENT_MAX', 120), help='The max length of the comment passed to Imperva')
    parser.add_argument('--caid', type=str, help='Specify the account ID')

    args = parser.parse_args()

    result = add_ip_exception(args.policy_id, args.ip_address, args.comment, args.base_url, args.api_id, args.api_key, args.caid, args.comment_max_len)
    pprint.pprint(result)


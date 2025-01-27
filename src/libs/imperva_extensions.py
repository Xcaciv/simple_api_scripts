import requests
import os
import argparse
import pprint
from argument_parser_extensions import *


# Function to get policy details
def get_policy(policy_id, base_url, api_id, api_key, caid=None, extended = True):
    """
    Retrieve a policy from the Imperva API.
    Args:
        policy_id (str): The ID of the policy to retrieve.
        base_url (str): The base URL of the API.
        api_id (str): The API ID for authentication.
        api_key (str): The API key for authentication.
        caid (str, optional): The CAID parameter to include in the request. Defaults to None.
        extended (bool, optional): Whether to include extended information in the response. Defaults to True.
    Returns:
        dict: The policy data retrieved from the API.
    Raises:
        Exception: If an error message is returned in the response or if the policy cannot be found.
    """
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

def get_ip_setting_id(policy):
    """
    Retrieve the ID of the IP setting from a given policy object.

    Args:
        policy (dict): A dictionary representing the policy, which contains a list of policy settings.

    Returns:
        str: The ID of the IP setting if found, otherwise None.
    """
    for setting in policy['policySettings']:
        if "policySettingType" in setting and setting['policySettingType'] == 'IP':
            return setting['id']
        
def get_policy_exception_setting_id(policy):
    """
    Retrieve the ID of the policy setting that contains policy data exceptions.

    Args:
        policy (dict): A dictionary representing the policy, which includes a list of policy settings.

    Returns:
        str: The ID of the policy setting that contains policy data exceptions, or None if not found.
    """
    for setting in policy['policySettings']:
        if "policyDataExceptions" in setting:
            return setting['id']
        
def create_ip_update_object(policy_id, policy_settings_id, ip_addresses):   
    """
    Create an IP update object for a given policy.

    Args:
        policy_id (str): The ID of the policy.
        policy_settings_id (str): The ID of the policy settings.
        ip_addresses (list): A list of IP addresses to be included in the policy.

    Returns:
        dict: A dictionary representing the IP update object with the specified policy ID, policy settings ID, and IP addresses.
    """
    return {
        "id": policy_id,
        "policySettings": [
              {
                "id": policy_settings_id, 
                "data": {
                    "ips": [
                        ip_addresses
                    ]
                }                       
              }
            ]
        }

def create_exception_update_object(policy_id, policy_settings_id, ip_addresses, comment, comment_max_len=120):   
    """
    Create an exception update object for a given policy.

    Args:
        policy_id (str): The ID of the policy.
        policy_settings_id (str): The ID of the policy settings.
        ip_addresses (list): A list of IP addresses to be added as exceptions.
        comment (str): A comment describing the exception.
        comment_max_len (int, optional): The maximum length of the comment. Defaults to 120.

    Returns:
        dict: A dictionary representing the exception update object.
    """
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

def add_ip(policy_id, ip_address, base_url, api_id, api_key, caid=None):
    """
    Adds an IP address to a specified policy.
    Args:
        policy_id (int): The ID of the policy to be modified.
        ip_address (str): The IP address to be added to the policy.
        base_url (str): The base URL for the API endpoint.
        api_id (str): The API ID for authentication.
        api_key (str): The API key for authentication.
        caid (int, optional): The CAID (Customer Account ID) if applicable. Defaults to None.
    Returns:
        dict: The response from the API after updating the policy.
    Raises:
        Exception: If there is an error in retrieving or updating the policy.
    Example:
        response = add_ip(1544495, '64.223.136.47', 'https://api.imperva.com', '127033', '0a838017-d68a-4df4-934b-8a97d02e40de', 1769792)
        print(response)
    """
    # curl -X 'POST' \
    #   'https://api.imperva.com/policies/v2/policies/1544495?caid=1769792' \
    #   -H 'accept: application/json' \
    #   -H 'x-API-Id: 127033' \
    #   -H 'x-API-Key: 0a838017-d68a-4df4-934b-8a97d02e40de' \
    #   -H 'Content-Type: application/json' \
    #   -d '{
    #   "policySettings": [
    #     {
    #       "id": 6347860,
    #       "data": {
    #         "ips": [
    #           "64.223.136.47"
    #         ]
    #       }
    #     }
    #   ]
    # }'
    policy = get_policy(policy_id, base_url, api_id, api_key, caid)
    print("Modifying policy: ", policy['description'])
    ip_setting_id = get_ip_setting_id(policy)
    add_ip_body = create_ip_update_object(policy_id, ip_setting_id, ip_address)

    return update_policy(base_url, policy_id, api_id, api_key, add_ip_body, caid)

# Function to update policy with new IP exception
def add_ip_exception(policy_id, ip_address, reason, base_url, api_id, api_key, caid=None, reason_max_len=120):
    """
    Add an IP address exception to a specified policy.
    Args:
        policy_id (int): The ID of the policy to modify.
        ip_address (str): The IP address to add as an exception.
        reason (str): The reason for adding the exception.
        base_url (str): The base URL for the API.
        api_id (str): The API ID for authentication.
        api_key (str): The API key for authentication.
        caid (int, optional): The CAID for the policy. Defaults to None.
        reason_max_len (int, optional): The maximum length for the reason. Defaults to 120.
    Returns:
        dict: The response from the API after updating the policy.
    """
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
    
    return update_policy(base_url, policy_id, api_id, api_key, exceptionBody, caid)

def update_policy(base_url, policy_id, api_id, api_key, update_body, caid=None):
    """
    Update an existing policy on the Imperva API.
    Args:
        base_url (str): The base URL of the Imperva API.
        policy_id (str): The ID of the policy to update.
        api_id (str): The API ID for authentication.
        api_key (str): The API key for authentication.
        update_body (dict): The JSON body containing the policy updates.
        caid (str, optional): The CAID parameter for the request. Defaults to None.
    Returns:
        dict: The JSON response from the API if the request is successful.
    Raises:
        Exception: If the API call fails.
    """
    
    url = f"{base_url}/v2/policies/{policy_id}?"
    if caid: url += f'caid={caid}'

    headers = {
        'Accept': 'application/json',
        'x-API-Id': api_id,
        'x-API-Key': api_key,
        'Content-Type': 'application/json'
    }
    try:
        response = requests.post(url, headers=headers, json=update_body)
        if response.ok:
            return response.json() 
        else:
            response.raise_for_status()
        
    except Exception as e:
        raise Exception('Failed API call to Imperva') from e        

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Add IP to an Imperva Policy.')
    parser.add_argument('-p','--policy_id', type=int, required=True, help='The ID of the policy')
    parser.add_argument('-ip','--ip_address', type=validate_ip_address_list, required=True, help='The IP address to add as an exception')
    parser.add_argument('-exception', action='store_true', help="Add exception for ip, and not block.")
    parser.add_argument('-c', '--comment', type=str_string_without_markup, help='Reason for the exception')
    parser.add_argument('--api_id', type=int, default=os.getenv('IMPERVA_API_ID'), help='API ID for authentication')
    parser.add_argument('--api_key', type=str_alnum, default=os.getenv('IMPERVA_API_KEY'), help='API key for authentication')
    parser.add_argument('--base_url', type=str_url, default=os.getenv('IMPERVA_BASE_URL', 'https://api.imperva.com/policies'), help='Base URL for the API')
    parser.add_argument('--comment_max_len', type=int, default=os.getenv('IMPERVA_COMMENT_MAX', 120), help='The max length of the comment passed to Imperva')
    parser.add_argument('--caid', type=int, help='Specify the account ID')

    parser.add_argument('--debug', action='store_true', help='Allow debug output and expanded exception display.')

    args = parser.parse_args()

    if args.exception:
        result = add_ip_exception(args.policy_id, args.ip_address, args.comment, args.base_url, args.api_id, args.api_key, args.caid, args.comment_max_len)
    else:
        result = add_ip(args.policy_id, args.ip_address, args.base_url, args.api_id, args.api_key, args.caid)
    pprint.pprint(result)


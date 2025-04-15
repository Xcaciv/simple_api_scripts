import requests
import os
import argparse


# Function to get policy details
def get_policy(policy_id):
    url = f"{BASE_URL}/v2/policies/{policy_id}"
    headers = {
        'x-API-Id': API_ID,
        'x-API-Key': API_KEY,
        'Content-Type': 'application/json'
    }
    response = requests.get(url, headers=headers)
    return response.json()

# Function to update policy with new IP exception
def add_ip_exception(policy_id, ip_address):
    policy = get_policy(policy_id)
    exceptions = policy.get('exceptions', [])
    exceptions.append(ip_address)
    
    update_data = {
        'exceptions': exceptions
    }
    
    url = f"{BASE_URL}/v2/policies/{policy_id}"
    headers = {
        'Authorization': f"Bearer {API_KEY}",
        'Content-Type': 'application/json'
    }
    response = requests.post(url, headers=headers, json=update_data)
    return response.json()

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Add IP exception to a policy.')
    parser.add_argument('-p','--policy_id', type=str, help='The ID of the policy')
    parser.add_argument('-ip','--ip_address', type=str, help='The IP address to add as an exception')
    parser.add_argument('--api_id', type=str, default=os.getenv('API_ID'), help='API ID for authentication')
    parser.add_argument('--api_key', type=str, default=os.getenv('API_KEY'), help='API key for authentication')
    parser.add_argument('--base_url', type=str, default=os.getenv('BASE_URL', 'https://api.imperva.com/policies'), help='Base URL for the API')

    args = parser.parse_args()

    API_ID = args.api_id
    API_KEY = args.api_key
    BASE_URL = args.base_url

    result = get_policy(args.policy_id)
    # result = add_ip_exception(args.policy_id, args.ip_address)
    print(result)


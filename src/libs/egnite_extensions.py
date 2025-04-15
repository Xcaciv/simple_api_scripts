#!/usr/bin/env python3
"""
Egnyte API extensions for file operations such as uploading files to Egnyte.
"""

import os
import sys
import argparse
import requests
import json
from typing import Dict, Any, Optional


class EgnyteClient:
    """Client for interacting with the Egnyte API."""

    def __init__(self, domain: str, access_token: str):
        """
        Initialize the Egnyte client.
        
        Args:
            domain: The Egnyte domain (e.g., 'acme.egnyte.com')
            access_token: OAuth access token for the Egnyte API
        """
        self.domain = domain
        self.access_token = access_token
        self.base_url = f"https://{domain}/pubapi"
        self.headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

    def upload_file(self, file_path: str, egnyte_path: str, 
                    overwrite: bool = False) -> Dict[str, Any]:
        """
        Upload a file to Egnyte.
        
        Args:
            file_path: Local path to the file to upload
            egnyte_path: Destination path in Egnyte
            overwrite: Whether to overwrite the file if it exists
            
        Returns:
            Response from the Egnyte API as a dictionary
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"The file {file_path} does not exist")

        # Construct the API endpoint URL
        file_name = os.path.basename(file_path)
        api_path = f"/v1/fs-content/{egnyte_path}/{file_name}"
        if not api_path.startswith('/v1/fs-content/'):
            api_path = '/v1/fs-content/' + api_path

        url = f"{self.base_url}{api_path}"
        
        # Set up query parameters
        params = {}
        if overwrite:
            params['force'] = 'true'
            
        # Read file content
        with open(file_path, 'rb') as file:
            file_content = file.read()
            
        # Set up headers for file upload (without Content-Type: application/json)
        upload_headers = {
            'Authorization': f'Bearer {self.access_token}'
        }
        
        # Make the API request
        response = requests.post(url, data=file_content, headers=upload_headers, params=params)
        
        # Check if request was successful
        if response.status_code not in [200, 201]:
            print(f"Error uploading file. Status code: {response.status_code}")
            print(f"Response: {response.text}")
            return {"success": False, "status_code": response.status_code, "message": response.text}
        
        return {"success": True, "status_code": response.status_code, "response": response.json()}


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments for the script.
    
    Returns:
        Parsed command-line arguments
    """
    parser = argparse.ArgumentParser(description='Upload files to Egnyte using the Egnyte API')
    
    parser.add_argument('--domain', required=True,
                        help='The Egnyte domain (e.g., acme.egnyte.com)')
    parser.add_argument('--token', required=True,
                        help='OAuth access token for the Egnyte API')
    parser.add_argument('--file', required=True,
                        help='Path to the local file to upload')
    parser.add_argument('--destination', required=True,
                        help='Destination path in Egnyte (e.g., /Shared/Documents)')
    parser.add_argument('--overwrite', action='store_true',
                        help='Overwrite the file if it already exists')
    
    return parser.parse_args()


def main():
    """Main entry point for the script when run from the command line."""
    args = parse_arguments()
    
    try:
        # Create Egnyte client
        client = EgnyteClient(args.domain, args.token)
        
        # Upload file
        print(f"Uploading {args.file} to Egnyte at {args.destination}...")
        result = client.upload_file(
            file_path=args.file,
            egnyte_path=args.destination,
            overwrite=args.overwrite
        )
        
        # Print result
        if result.get("success"):
            print(f"File uploaded successfully!")
            print(f"Response: {json.dumps(result.get('response', {}), indent=2)}")
        else:
            print(f"Failed to upload file: {result.get('message', 'Unknown error')}")
            sys.exit(1)
    
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Slack API extensions for file operations such as uploading files to Slack.
"""

import os
import sys
import argparse
import requests
import json
from typing import Dict, Any, Optional


class SlackClient:
    """Client for interacting with the Slack API."""

    def __init__(self, token: str):
        """
        Initialize the Slack client.
        
        Args:
            token: Slack API token (typically begins with xoxb-, xoxp-, or xapp-)
        """
        self.token = token
        self.headers = {
            'Authorization': f'Bearer {token}',
        }
        self.base_url = "https://slack.com/api"

    def upload_file(self, file_path: str, channels: str, 
                   title: Optional[str] = None, 
                   initial_comment: Optional[str] = None,
                   thread_ts: Optional[str] = None) -> Dict[str, Any]:
        """
        Upload a file to Slack.
        
        Args:
            file_path: Path to the local file to upload
            channels: Comma-separated list of channel IDs/names to share the file with
            title: Title for the file (optional)
            initial_comment: Comment to add to the file (optional)
            thread_ts: Thread timestamp to reply to (optional)
            
        Returns:
            Response from the Slack API as a dictionary
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"The file {file_path} does not exist")

        # Set up the upload endpoint
        url = f"{self.base_url}/files.upload"
        
        # Set up form data for the request
        form_data = {
            'channels': channels,
        }
        
        # Add optional parameters if provided
        if title:
            form_data['title'] = title
        if initial_comment:
            form_data['initial_comment'] = initial_comment
        if thread_ts:
            form_data['thread_ts'] = thread_ts
        
        # Open the file for upload
        with open(file_path, 'rb') as file_content:
            files = {
                'file': (os.path.basename(file_path), file_content, 'application/octet-stream')
            }
            
            # Make the API request
            response = requests.post(url, headers=self.headers, data=form_data, files=files)
        
        # Parse response
        response_data = response.json()
        
        # Check if request was successful
        if not response_data.get('ok', False):
            error_message = response_data.get('error', 'Unknown error')
            print(f"Error uploading file to Slack: {error_message}")
            return {
                "success": False,
                "error": error_message,
                "response": response_data
            }
        
        return {
            "success": True,
            "response": response_data
        }


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments for the script.
    
    Returns:
        Parsed command-line arguments
    """
    parser = argparse.ArgumentParser(description='Upload files to Slack using the Slack API')
    
    parser.add_argument('--token', required=True,
                        help='Slack API token (xoxb-, xoxp-, or xapp-)')
    parser.add_argument('--file', required=True,
                        help='Path to the local file to upload')
    parser.add_argument('--channels', required=True,
                        help='Comma-separated list of channel IDs/names to share the file with')
    parser.add_argument('--title',
                        help='Title for the file (optional)')
    parser.add_argument('--comment',
                        help='Initial comment for the file (optional)')
    parser.add_argument('--thread',
                        help='Thread timestamp to reply to (optional)')
    
    return parser.parse_args()


def main():
    """Main entry point for the script when run from the command line."""
    args = parse_arguments()
    
    try:
        # Create Slack client
        client = SlackClient(args.token)
        
        # Upload file
        print(f"Uploading {args.file} to Slack channels: {args.channels}...")
        result = client.upload_file(
            file_path=args.file,
            channels=args.channels,
            title=args.title,
            initial_comment=args.comment,
            thread_ts=args.thread
        )
        
        # Print result
        if result.get("success"):
            file_info = result.get("response", {}).get("file", {})
            file_name = file_info.get("name", "Unknown")
            permalink = file_info.get("permalink", "No permalink available")
            
            print(f"File '{file_name}' uploaded successfully!")
            print(f"Permalink: {permalink}")
        else:
            print(f"Failed to upload file: {result.get('error', 'Unknown error')}")
            sys.exit(1)
    
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()

import argparse
import requests

def list_files_in_repo(repo_owner, repo_name, file_mask):
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents"
    response = requests.get(url)
    response.raise_for_status()
    files = response.json()
    
    matching_files = []
    for file in files:
        if file_mask in file['name']:
            matching_files.append(file['name'])
    
    return matching_files

if __name__ == "__main__":
    # Create the argument parser
    parser = argparse.ArgumentParser(description="List files in a GitHub repo that match a given file name mask")
    
    # Add the command line arguments
    parser.add_argument("repo_owner", help="Owner of the GitHub repository")
    parser.add_argument("repo_name", help="Name of the GitHub repository")
    parser.add_argument("file_mask", help="File name mask to match")
    
    # Parse the command line arguments
    args = parser.parse_args()
    
    # Call the function with the provided arguments
    matching_files = list_files_in_repo(args.repo_owner, args.repo_name, args.file_mask)
    print(matching_files)

import os
import sys
import argparse
import requests
from github import Github
from github import Auth
import glob
def list_files_in_github_repo(repo_owner, repo_name, file_mask, ghClient):

    # Get the repository
    repo = ghClient.get_repo(f"{repo_owner}/{repo_name}")
    searchResults = ghClient.search_code(query=f"{repo_owner}/{repo_name} file:{file_mask}")
    repo.search_code(query=f"{repo_owner}/{repo_name} file:{file_mask}")    

    matching_files = []
    # Iterate over the repository contents
    for content in searchResults.get_contents(""):
        # Check if the content is a file and matches the file mask
        if content.type == "file" and file_mask in content.name:
            matching_files.append(content.name)

    return matching_files

def list_files_in_local_path(local_path, file_mask):
    """
    List files in the specified local path that match the given file mask.
    Args:
        local_path (str): The local path to search for files.
        file_mask (str): The file mask to match against file names.
    Returns:
        list: A list of file names that match the file mask.
    """
    # Use glob to find files that match the file mask
    return glob.glob(f"{local_path}/{file_mask}", recursive=True)

if __name__ == "__main__":
    # Create the argument parser
    parser = argparse.ArgumentParser(description="List files in a GitHub repo that match a given file name mask")

    # Add the command line arguments
    parser.add_argument("file_mask", type=str, help="File name mask to match")
    parser.add_argument("-local_path", type=str, help="Local path to save the downloaded files")
    parser.add_argument("-github", action="store_true", default=False, help="Flag to indicate if the repository is on GitHub")
    parser.add_argument("-repo_owner", type=str, help="Owner of the GitHub repository")
    parser.add_argument("-repo_name", type=str, help="Name of the GitHub repository")
    parser.add_argument('--access_token', type=str, default=os.getenv('GITHUB_ACCESS_TOKEN'),
                        help='Github access token')

    # Parse the command line arguments
    args = parser.parse_args()

    if not args.github and args.local_path is None:
        parser.print_help()
        sys.exit(1)

    if args.github and (args.repo_name is None or args.repo_owner is None or args.access_token is None):
        parser.print_help()
        sys.exit(1) 

    print(f"searching for files with mask {args.file_mask}")

    if args.github:
        print (f"searching in github repo {args.repo_owner}/{args.repo_name}")
        auth = Auth.Token(args.access_token)
        # Create a Github instance
        ghClient = Github(auth=auth)

        # Call the function with the provided arguments
        matching_files = list_files_in_github_repo(args.repo_owner, args.repo_name, args.file_mask, ghClient)
    else:
        print (f"searching in local path {args.local_path}")
        # Call the function with the provided arguments
        matching_files = list_files_in_local_path(args.local_path, args.file_mask)
    
    print(matching_files)



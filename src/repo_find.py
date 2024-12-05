import os
import sys
import argparse
import tempfile
import time
from github import Github, RateLimitExceededException
from github import Auth
import glob

import yaml

def process_catalog(file_content):
    """
    Process the catalog file content and return the team string
    Args:
        file_content (str): The content of the catalog file
    Returns:
        str: The team string
    """
    # Load the yaml content
    yaml_content = yaml.safe_load(file_content)
    # Check if there is an 'include' key in the yaml content
    if 'include' in yaml_content:
        include_value = yaml_content.get('include')
        team = f"INCLUDE:{include_value}"
    else:
        # Get the value for 'team' from the yaml content
        team = yaml_content.get('team')
    
    return team

def resolve_include_github(include_value, repo_owner, repo_name, ghClient):
    """
    Resolve the include value by searching for the file in the GitHub repository
    Args:
        include_value (str): The include value to resolve
        ghClient: An instance of the GitHub client
    Returns:
        str: The resolved team string
    """
    
    include_file_path = include_value.replace("INCLUDE:", "")

    fileQuery = f"repo:{repo_owner}/{repo_name} filename:{include_file_path}"
    print(f"searching for include file with query {fileQuery}")

    # make the call to the GitHub API to search for code
    # and handle timeouts and rate limits
    try:
        searchResults = ghClient.search_code(query=fileQuery) 
    except RateLimitExceededException:
        print("Rate limit exceeded, cooling down...")
        core_rate_limit = ghClient.get_rate_limit().core
        reset_timestamp = core_rate_limit.reset.timestamp()
        current_timestamp = time.time()
        wait_time = reset_timestamp - current_timestamp
        time.sleep(wait_time + 1)  
        return resolve_include_github(include_value, repo_owner, repo_name, ghClient)

    teamstring = ''

    for file in searchResults:
        teamstring = process_catalog(file.decoded_content.decode())

    if teamstring.startswith("INCLUDE:"):
        raise Exception("Include value cannot be resolved")
    
    return teamstring
    

def process_files_in_github_repo(repo_owner, repo_name, file_name, ghClient, depth):
    """
    Retrieves a list of files in a GitHub repository that match a given file mask.
    Parameters:
    - repo_owner (str): The owner of the GitHub repository.
    - repo_name (str): The name of the GitHub repository.
    - file_name (str): The file name to match against the file.
    - ghClient: An instance of the GitHub client.
    Returns:
    - temp_file_path (list): A file containing a list of file names that match
    """

    # open a os temp file for paths to
    temp_file = tempfile.NamedTemporaryFile(delete=False, prefix="team_index_", suffix=".txt")
    temp_file_path = temp_file.name
    
    fileQuery = f"repo:{repo_owner}/{repo_name} filename:{file_name}"
    print(f"searching for files with query: {fileQuery}")

    # make the call to the GitHub API to search for code
    # and handle timeouts and rate limits
    try:
        searchResults = ghClient.search_code(query=fileQuery)    
        # Iterate over the repository contents to get file paths
        for file in searchResults:
            # extract team name from content
            teamstring = process_catalog(file.decoded_content.decode())
            if teamstring.startswith("INCLUDE:"):
                # resolve team from the include file
                teamstring = resolve_include_github(teamstring, ghClient)

            repo_file_path = apply_depth(os.path.dirname(file.path), depth)
            # add path to index
            temp_file.write(f"{repo_file_path}|{teamstring}\n".encode())

    except RateLimitExceededException:
        print("Rate limit exceeded, cooling down...")
        core_rate_limit = ghClient.get_rate_limit().core
        reset_timestamp = core_rate_limit.reset.timestamp()
        current_timestamp = time.time()
        wait_time = reset_timestamp - current_timestamp
        time.sleep(wait_time + 1)  
        return process_files_in_github_repo(repo_owner, repo_name, file_name, ghClient)
    
    temp_file.close()
    return temp_file_path

def resolve_include_local_path(include_value, local_path):
    """
    Resolve the include value by searching for the file in the local path.
    Args:
        include_value (str): The include value to resolve.
        local_path (str): The local path to search for the include file.
    Returns:
        str: The resolved team string.
    """
    include_file_path = include_value.replace("INCLUDE:", "")
    teamstring = ''

    for file in glob.glob(f"{local_path}/../**/{include_file_path}", recursive=True):
        # resolve the file path to get the absolute path
        file_path = os.path.abspath(file)
        with open(file_path, 'r') as f:
            file_content = f.read()
            teamstring = process_catalog(file_content)
    
    if teamstring.startswith("INCLUDE:"):
        raise Exception("Include value cannot be resolved")

    return teamstring

def process_files_in_local_path(local_path, file_mask, depth):
    """
    List files in the specified local path that match the given file mask.
    Args:
        local_path (str): The local path to search for files.
        file_mask (str): The file mask to match against file names.
        depth (int): The maximum index depth.
    Returns:
        list: A list of file names that match the file mask.
    """

    # open a os temp file for paths to
    temp_file = tempfile.NamedTemporaryFile(delete=False, prefix="team_index_", suffix=".txt")
    temp_file_path = temp_file.name
    
    print(f"searching for files with mask {file_mask} in local path {local_path}")
    # Use glob to find files that match the file mask
    for file in glob.glob(f"{file_mask}", recursive=True, root_dir=local_path):
        # resolve the file path to get the absolute path
        file_path = os.path.abspath(os.path.join(local_path, file))

        print(f"processing file: {file_path} ({file})")
        with open(file_path, 'r') as f:
            file_content = f.read()
            teamstring = process_catalog(file_content)
            if teamstring.startswith("INCLUDE:"):
                # resolve team from the include file
                teamstring = resolve_include_local_path(teamstring, local_path)

        repo_file_path = file_path.replace(local_path, "")
        print(f"repo_file_path: {repo_file_path}")
        print("------------------")

        repo_file_path = apply_depth(os.path.dirname(repo_file_path), depth)

        # add path to index
        temp_file.write(f"{repo_file_path}|{teamstring}\n".encode())

    print (f"temp file path: {temp_file_path}")    
    temp_file.close()
    return temp_file_path

def apply_depth(repo_file_path, depth):
    """
    Apply the depth to the repo_file_path.
    Args:
        repo_file_path (str): The repository file path.
        depth (int): The depth to apply. negative numbers count from the end of the path backwards.
    Returns:
        str: The modified repository file path.
    """
    # determine the path seperator is forward or backward slash by checking if the path contains a backslash
    seperator = ("\\" if "\\" in repo_file_path else "/")
    # remove the first character if it is a slash
    if repo_file_path[0] == seperator:
        repo_file_path = repo_file_path[1:]
    # split the path into parts
    path_parts = repo_file_path.split(seperator)
    # check if the path is deeper than the specified depth

    if depth == 0:
        return repo_file_path
    if depth > 0:
        return seperator.join(path_parts[depth:]) + seperator
    else:
        return seperator.join(path_parts[:depth]) + seperator

if __name__ == "__main__":
    # Create the argument parser
    parser = argparse.ArgumentParser(description="Create a catalog of directories owned by teams from a repository. You can specify a local path or a GitHub repository.")

    # Add the command line arguments
    parser.add_argument("-file_name", type=str, default="catalog.yml", help="File name to find in the repository")
    parser.add_argument("-local_path", type=str, help="Local path to save the downloaded files")
    parser.add_argument("-github", action="store_true", default=False, help="Flag to indicate if the repository is on GitHub")
    parser.add_argument("-repo_owner", type=str, help="Owner of the GitHub repository")
    parser.add_argument("-repo_name", type=str, help="Name of the GitHub repository")
    parser.add_argument('--access_token', type=str, default=os.getenv('GITHUB_ACCESS_TOKEN'),
                        help='Github access token')
    parser.add_argument("-max-depth", type=int, default=-1, 
                        help="Maximum index depth. Default is -1 (negative numbers count from the directory containing the catalog file, positive count from the repository root).")

    # Parse the command line arguments
    args = parser.parse_args()

    if not args.github and args.local_path is None:
        parser.print_help()
        sys.exit(1)

    if args.github and (args.repo_name is None or args.repo_owner is None or args.access_token is None):
        parser.print_help()
        sys.exit(1) 

    print(f"searching for files with name {args.file_name}")

    if args.github:
        print (f"TARGET: github repo {args.repo_owner}/{args.repo_name}")
        auth = Auth.Token(args.access_token)
        # Create a Github instance
        ghClient = Github(auth=auth)

        # Call the github function
        matching_files_index = process_files_in_github_repo(args.repo_owner, args.repo_name, args.file_name, ghClient, args.max_depth)     

    else:
        print (f"TARGET: local path {args.local_path}")

        # Call the local_path function
        matching_files_index = process_files_in_local_path(args.local_path, f"**/{args.file_name}", args.max_depth)
    
    print ("FINISHED indexing teams --")
    print ("using temp file:")
    print(matching_files_index)
    
    # Set the environment variable
    os.environ["TMP_TEAM_INDX"] = matching_files_index



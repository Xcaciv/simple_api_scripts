import argparse
import os
import pandas
import warnings
import base64
from jira import JIRA

def download_ticket_data(jql, fields=["summary","assignee","created","resolutiondate"], file_name="jira_output.csv", page_size=100, jira_connection=None, jira_srver=None, jira_token=None, jira_user=None, localserver=False, overtwie=True):
    """
    Downloads ticket data from Jira based on the provided JQL query and saves it in a CSV file.

    Args:
        jql (str): Jira Query Language (JQL) to search for issues.
        fields (list, optional): List of fields to include in the CSV. Defaults to ["key", "summary","assignee","created","resolutiondate"].
        file_name (str, optional): Name of the CSV file to save the data. Defaults to "jira_output.csv".
        page_size (int, optional): Page size for pagination. Defaults to 100.
        status_callback (function, optional): Callback function to display status messages. Defaults to None.
        jira_connection (JIRA, optional): Existing JIRA connection object. Defaults to None.
        jira_srver (str, optional): Jira server URL. Defaults to None.
        pat (str, optional): Jira personal access token. Defaults to None.
        localserver (bool, optional): Flag to indicate if running on a local server. Defaults to False.
    """
    

    if jira_connection is None:
        basicAuth = None
        if not (jira_user is None or jira_user == "nouser"):
            basicAuth = (jira_user, jira_token)
            options = {
                'server': jira_srver,
                'headers': {
                    'Accept': 'application/json'
                },
            }
        else:
            options = {
                'server': jira_srver,
                'headers': {
                    'Authorization': f'Bearer {jira_token}',
                    'Accept': 'application/json'
                },
            }

        if localserver:
            options['verify'] = False
            restore_warning = warnings.showwarning
            warnings.showwarning = lambda *args, **kwargs: None

        if status_callback:
            status_callback(f"Connecting to Jira server {jira_srver}")

        try:
            jira_connection = JIRA(options, max_retries=0, basic_auth=basicAuth)
        except Exception as ex:
            if status_callback:
                status_callback(f"Error connecting to Jira server: {ex}")
            return

    if status_callback:
        status_callback("Searching Jira Issues...")

    try:
        # Execute JQL query with pagination
        issues = jira_connection.search_issues(jql, fields=fields, maxResults=page_size)
    except Exception as ex:
        if status_callback:
            status_callback(f"Error searching Jira issues: {ex}")
        return


    total_issues = issues.total
    if total_issues >0:
        # Calculate the number of pages based on the page size
        num_pages = (total_issues // page_size) + 1
    else:
        if status_callback:
            status_callback("No issues found")
        return
    
    if status_callback:
        status_callback("Found {} issues".format(total_issues))
        status_callback("Saving page {} of {}".format(1, num_pages))

    if overtwie and os.path.isfile(file_name):
        status_callback("Overwriting {file_name}")
        os.remove(file_name)

    # Extract data and convert to DataFrame
    write_issues_to_csv(issues, fields, file_name, True)
        
    # Loop over each page and save it as a chunk in the CSV
    for page in range(1, num_pages):
        # Execute JQL query with pagination
        start_at = page * page_size

        try:
            issues = jira_connection.search_issues(jql, fields=fields, startAt=start_at, maxResults=page_size)
        except Exception as ex:
            if status_callback:
                status_callback(f"Error searching Jira issues: {ex}")
            return

        if status_callback:
            status_callback("Saving page {} of {}".format(page + 1, num_pages))

        write_issues_to_csv(issues, fields, file_name, False)

    if localserver:
        warnings.showwarning = restore_warning

def write_issues_to_csv(issues, fields, file_name, csv_header):
    """
    Writes the Jira issues data to a CSV file.

    Args:
        issues (list): List of Jira issues.
        fields (list): List of fields to include in the CSV.
        file_name (str): Name of the CSV file.
        csv_header (bool): Flag to indicate if the CSV file should include a header row.
    """
    data = []
    for issue in issues:
        issueInfo = {"Issue key": issue.key, "Issue id": issue.id}
        row = {field: issue.fields.__dict__.get(field) for field in fields}
        # make sure key and id are the first columns
        row = {**issueInfo, **row}
        data.append(row)
    df = pandas.DataFrame(data)
    
    # Save each page in a CSV chunk using pandas
    df.to_csv(file_name, mode='a', index=False, header=csv_header)

def print_issue_fields(jira_connection, jira_issue):
    try:
        
        all_fields = { field['id'] : field['name'] for field in jira_connection.fields() }
        issue = jira_connection.issue(jira_issue)
        for field_id in issue.raw['fields']:
            print(f'Field id: {field_id} Name:' all_fields[field_id] if field_id in all_fields else 'na', f' Value: {issue.raw['fields'][field_id]}')
        
    except JIRAError as jex:
        raise Exception(f'Failed to list issue {jira_issue} fields: {jex.text}') from jex
    except Exception as e:
        raise Exception(f'Failed to list issue {jira_issue} fields.') from e
        
def print_issue_transitions(jira_connection, jira_issue):
    try:
        
        transitions = jira_connection.transitions(jira_issue)
        for transition in transitions:
            print(f'Transition Id: {transition['id']}    Name: {transition['name']}')
            
    except JIRAError as jex:
        raise Exception(f'Failed to list issue {jira_issue} transitions: {jex.text}') from jex
    except Exception as e:
        raise Exception(f'Failed to assign issue {jira_issue} transitions.') from e

def assign_user(jira_connection, jira_issue, jira_user):
    try:
        jira_connection.assign_issue(jira_issue, jira_user)
    except JIRAError as jex:
        raise Exception(f'Failed to assign issue {jira_issue} to user {jira_user}: {jex.text}') from jex
    except Exception as e:
        raise Exception(f'Failed to assign issue {jira_issue} to user {jira_user}.') from e
        

def jira_response_check(jira_response):
    try:
        
        if jira_response == None:
            return
        elif 'errorMessages' in jira_response and jira_response['errorMessages'].len():
            raise Exception(jira_response['errorMessages'])
        elif 'errors' in jira_response and jira_response['errors'].len():
            raise Exception(jira_response['errors'])
        
    except:
        raise ValueError("Invalid Jira response.")

def is_base64(s):
    try:
        return base64.b64encode(base64.b64decode(s)).decode() == s
    except Exception:
        return False

def MaybeBase64(s):
    try:
        if is_base64(s):
            return base64.b64decode(s)
        else:
            return s
    except Exception:
        return s
    
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', "--jira_server", help="Jira server URL")
    parser.add_argument('-t', "--jira_token", help="Jira personal access token")
    parser.add_argument('-q', "--jql", help="Jira Query Language (JQL). can be encoded in Base64 or enclosed in double quotes with single quotes in the query")
    
    parser.add_argument('-u', "--jira_user", help="Jira user if using Jira Cloud basic auth", default="nouser")

    parser.add_argument("--file_name", help="Name of the CSV", default="jira_output.csv")
    parser.add_argument("--page_size", type=int, help="Page size for pagination", default=100)
    parser.add_argument("--fields", help="Fields to include in the CSV", default=["summary","assignee","created","description","status"])
    parser.add_argument('--localserver', action='store_true', help='Flag to indicate a self-signed certificate')
    parser.add_argument('--overwrite', action='store_true', help='Flag to indicate output file should be overwritten')
    args = parser.parse_args()

    # Get the parameters from the command line using argparse
    jira_server = args.jira_server or os.environ.get("JIRA_SERVER")
    jira_token = args.jira_token or os.environ.get("JIRA_TOKEN")
    jql = MaybeBase64(args.jql)

    if not jira_server:
        print("Jira server must be specified via parameter or JIRA_SERVER environment variable")
        parser.print_help()
        return
    
    if not jira_token:
        print("Jira token must be specified via parameter or JIRA_TOKEN environment variable")
        parser.print_help()
        return
    
    if os.path.isfile(args.file_name) and args.overwrite:
        os.remove(args.file_name)


    print("Downloading ticket data to {args.file_name}")

    # Call the method to download ticket data from Jira and save it in a CSV
    download_ticket_data(
        jql,
        args.fields,
        args.file_name,
        args.page_size,
        jira_srver=jira_server,
        jira_token=jira_token,
        jira_user=args.jira_user,
        localserver=args.localserver,
    )

if __name__ == "__main__":
    main()

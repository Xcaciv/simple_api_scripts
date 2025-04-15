import argparse
import os
import base64
import warnings
from jira import JIRA, JIRAError
from atlassian import ServiceDesk
import csv
import logging
from libs.argument_parser_extensions import *

def download_issue_data(jql, fields=["summary","assignee","created"], file_name="jira_output.csv", page_size=100, expand_fields=None, jira_connection=None, jira_server=None, jira_token=None, jira_user=None, localserver=False, overwrite_existing=True):
    """
    Downloads issue data from Jira based on a JQL query and saves it to a CSV file.
    Args:
        jql (str): The JQL query to search for issues.
        fields (list, optional): List of fields to retrieve for each issue. Defaults to ["summary", "assignee", "created"].
        file_name (str, optional): The name of the output CSV file. Defaults to "jira_output.csv".
        page_size (int, optional): The number of issues to retrieve per page. Defaults to 100.
        expand_fields (list, optional): List of fields to expand in the search results. Defaults to None.
        jira_connection (JIRA, optional): An existing Jira connection object. If None, a new connection will be created. Defaults to None.
        jira_server (str, optional): The Jira server URL. Required if jira_connection is None. Defaults to None.
        jira_token (str, optional): The Jira API token. Required if jira_connection is None. Defaults to None.
        jira_user (str, optional): The Jira username. Required if jira_connection is None. Defaults to None.
        localserver (bool, optional): Whether to suppress warnings for local server connections. Defaults to False.
        overwrite_existing (bool, optional): Whether to overwrite the existing CSV file if it exists. Defaults to True.
    Returns:
        None
    """
    
    if jira_connection is None:
        jira_connection = get_jira_connection(jira_server, jira_user, jira_token, localserver)
    if localserver:
        restore_warning = warnings.showwarning
        warnings.showwarning = lambda *args, **kwargs: None

    logging.info("Searching Jira Issues...")

    try:
        # Execute JQL query with pagination
        issues = jira_connection.search_issues(jql, fields=fields, maxResults=page_size, expand=expand_fields)
    except Exception as ex:
        logging.info(f"Error searching Jira issues: {ex}")
        return

    total_issues = issues.total
    if total_issues > 0:
        # Calculate the number of pages based on the page size
        num_pages = (total_issues // page_size) + 1
    else:
        logging.info("No issues found")
        return
    
    logging.info("Found {} issues".format(total_issues))
    logging.info("Saving page {} of {}".format(1, num_pages))

    if overwrite_existing and os.path.isfile(file_name):
        logging.info(f"Overwriting {file_name}")
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
            logging.info(f"Error searching Jira issues: {ex}")
            return

        logging.info("Saving page {} of {}".format(page + 1, num_pages))

        write_issues_to_csv(issues, fields, file_name, False)

    if localserver:
        warnings.showwarning = restore_warning

def write_issues_to_csv(issues, fields, file_name, csv_header):
    """
    Writes a list of JIRA issues to a CSV file.
    Args:
        issues (list): A list of JIRA issue objects.
        fields (list): A list of field names to include in the CSV.
        file_name (str): The name of the CSV file to write to.
        csv_header (bool): If True, write the CSV header.
    Returns:
        None
    """

    with open(file_name, mode='a', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["Issue key", "Issue id"] + fields)
        
        if csv_header:
            writer.writeheader()
        
        for issue in issues:
            issueInfo = {"Issue key": issue.key, "Issue id": issue.id}
            row = {field: issue.fields.__dict__.get(field) for field in fields}
            # make sure key and id are the first columns
            row = {**issueInfo, **row}
            writer.writerow(row)

def get_jira_connection(jira_server, jira_user, jira_token, localserver=False):
    """
    Establishes a connection to a Jira server.
    Args:
        jira_srver (str): The URL of the Jira server.
        jira_user (str): The username for Jira authentication. If set to "nouser" or None, token-based authentication is used.
        jira_token (str): The API token or password for Jira authentication.
        localserver (bool, optional): If True, SSL verification is disabled. Defaults to False.
    Returns:
        JIRA: An instance of the JIRA client if the connection is successful.
        None: If there is an error connecting to the Jira server.
    Raises:
        Exception: If there is an error connecting to the Jira server.
    """
    
    basicAuth = None
    if not (jira_user is None or jira_user == "nouser"):
        basicAuth = (jira_user, jira_token)
        options = {
            'server': jira_server,
            'headers': {
                'Accept': 'application/json'
            },
        }
    else:
        options = {
            'server': jira_server,
            'headers': {
                'Authorization': f'Bearer {jira_token}',
                'Accept': 'application/json'
            },
        }

    if localserver:
        options['verify'] = False

    logging.info(f"Connecting to Jira server {jira_server}")

    try:
        return JIRA(options, max_retries=0, basic_auth=basicAuth)
    except Exception as ex:
        logging.info(f"Error connecting to Jira server: {ex}")
        return

def jira_set_issue_status(jira_issue, jira_status, comment=None, jira_server=None, jira_user=None, jira_token=None, jira_connection=None, localserver=False, fields=None):
    """
    Transition a JIRA issue to a new status with optional comment and additional fields.
    Args:
        jira_issue (str): The ID or key of the JIRA issue to transition.
        jira_status (str): The name or ID of the status to transition the issue to.
        comment (str, optional): A comment to add to the issue during the transition. Defaults to None.
        jira_server (str, optional): The URL of the JIRA server. Required if jira_connection is not provided. Defaults to None.
        jira_user (str, optional): The JIRA username for authentication. Required if jira_connection is not provided. Defaults to None.
        jira_token (str, optional): The JIRA API token for authentication. Required if jira_connection is not provided. Defaults to None.
        jira_connection (JIRA, optional): An existing JIRA connection object. If provided, jira_server, jira_user, and jira_token are ignored. Defaults to None.
        localserver (bool, optional): If True, suppresses warnings for local server usage. Defaults to False.
        fields (dict, optional): Additional fields to set during the transition. Defaults to None.
    Returns:
        dict: The result of the transition operation, or None if the transition failed.
    Raises:
        Exception: If there is an error transitioning the issue, with details from the JIRAError or general Exception.
    """

    try:
        if jira_connection is None:
            jira_connection = get_jira_connection(jira_server, jira_user, jira_token, localserver)
    except:
        logging.info(f"Error connecting to Jira server: {ex}")
        logging.exception()
        return

    if localserver:
        restore_warning = warnings.showwarning
        warnings.showwarning = lambda *args, **kwargs: None

    result = None

    try:

        result = jira_connection.transition_issue(jira_issue, jira_status, fields=fields, comment=comment)
        
    except JIRAError as jex:
        raise Exception(f'Error Transitioning issue: {jex.text}') from jex
    except Exception as ex:
        raise Exception(f'Error Transitioning issue: {ex}') from ex

    if localserver:
        warnings.showwarning = restore_warning

    return result

def jira_add_issue_comment(jira_issue, comment="Transitioned via script", jira_server=None, jira_user=None, jira_token=None, jira_connection=None, localserver=False):
    """
    Adds a comment to a specified Jira issue.
    Args:
        jira_issue (str): The Jira issue key or ID to add the comment to.
        comment (str, optional): The comment text to add. Defaults to "Transitioned via script".
        jira_server (str, optional): The Jira server URL. Required if jira_connection not provided.
        jira_user (str, optional): The Jira username. Required if jira_connection not provided.
        jira_token (str, optional): The Jira API token. Required if jira_connection not provided.
        jira_connection (JIRA, optional): An existing JIRA connection object. If not provided, a new connection will be created.
        localserver (bool, optional): Flag indicating if connecting to a local server. Defaults to False.
    Returns:
        Comment: The created comment object.
    Raises:
        Exception: If there is an error adding the comment to the Jira issue.
    """

    if jira_connection is None:
        jira_connection = get_jira_connection(jira_server, jira_user, jira_token, localserver)
    if localserver:
        restore_warning = warnings.showwarning
        warnings.showwarning = lambda *args, **kwargs: None

    try:
        return jira_connection.add_comment(jira_issue, comment)
    except JIRAError as jex:
        raise Exception(f'Error adding Jira comment: {jex.text}') from jex
    except Exception as ex:
        raise Exception(f"Error adding Jira comment: {ex}") from ex

    if localserver:
        warnings.showwarning = restore_warning

def jira_update_field(jira_server, jira_user, jira_token, jira_issue, field_to_set, field_value_name=None, field_value_id=None, jira_connection=None, localserver=False, fields=None):
    """
    Updates a field in a Jira issue with the specified value.
    Args:
        jira_server (str): URL of the Jira server
        jira_user (str): Jira username or email
        jira_token (str): Jira API token or password
        jira_issue (str): Jira issue key/ID to update
        field_to_set (str): Name of the field to update
        field_value_name (str, optional): Display name of the field value to set. Defaults to None.
        field_value_id (str, optional): ID of the field value to set. Defaults to None.
        jira_connection (jira.JIRA, optional): Existing Jira connection object. Defaults to None.
        localserver (bool, optional): Flag indicating if connecting to a local server. Defaults to False.
        fields (dict, optional): Additional fields for the Jira connection. Defaults to None.
    Returns:
        dict: Result of the field update operation from Jira
    Raises:
        Exception: If there is an error updating the Jira field value
    """
    if jira_connection is None:
        jira_connection = get_jira_connection(jira_server, jira_user, jira_token, localserver)
    if localserver:
        restore_warning = warnings.showwarning
        warnings.showwarning = lambda *args, **kwargs: None

    try:
        jira_result = update_field_value(jira_connection, jira_issue, field_to_set, field_value_name, field_value_id)

    except JIRAError as jex:
        raise Exception(f'Error updating Jira field value: {jex.text}') from jex
    except Exception as ex:
        logging.info(f"Error updating Jira field value: {ex}")

    if localserver:
        warnings.showwarning = restore_warning
    
    return jira_result

def update_field_value(jira_connection, jira_issue, field_to_set, field_value_name=None, field_value_id=None, ):
    """
    Updates a field value in a Jira issue using either an ID or name value.

    Args:
        jira_connection: Active JIRA connection object
        jira_issue: The JIRA issue key or ID to update
        field_to_set: Name of the field to be updated
        field_value_name: Optional name value to set the field to
        field_value_id: Optional ID value to set the field to

    Returns:
        The result of the issue.update() call

    Raises:
        JIRAError: If the update fails or connection issues occur

    Notes:
        Either field_value_name or field_value_id should be provided, not both
        For custom fields, field_to_set should include the customfield_ prefix
    """
    issue = jira_connection.issue(jira_issue) #, field=field_to_set
    if field_value_id:
        logging.debug('setting value by id')
        return issue.update(fields={ field_to_set : {'id': field_value_id} })
    elif field_value_name:
        logging.debug('setting value by name')
        return issue.update(fields={ field_to_set : {'value': field_value_name} })

def list_issue_fields(jira_connection, jira_issue):
    """
    Lists all fields and their values for a given Jira issue.
    Args:
        jira_connection: An authenticated JIRA connection object
        jira_issue: String representing the Jira issue key (e.g. 'PROJ-123')
    Raises:
        Exception: If there is a JIRAError or other error while fetching issue fields
    Example:
        >>> jira_conn = JIRA('https://jira.example.com', auth=('user', 'pass'))
        >>> list_issue_fields(jira_conn, 'PROJ-123')
        Field: summary Name: Summary Value: Issue title
        Field: status Name: Status Value: Open
        ...
    """
    try:

        all_fields = {field['id']: field['name'] for field in jira_connection.fields()}
        issue = jira_connection.issue(jira_issue)
        for field_id in issue.raw['fields']:
            print("Field: ", field_id, " Name: ", all_fields[field_id] if field_id in all_fields else 'na', " Value: ", issue.raw['fields'][field_id])

    except JIRAError as jex:
        raise Exception(f'Failed to list issue {jira_issue} fields: {jex.text}') from jex
    except Exception as e:
        raise Exception(f'Failed to list issue {jira_issue} fields') from e

def list_issue_transitions(jira_connection, jira_issue):
    """
    Lists all available transitions for a given JIRA issue.

    This function retrieves and prints all possible status transitions for a specified JIRA issue,
    showing both the transition ID and name for each available transition.

    Args:
        jira_connection: A JIRA connection object used to interact with the JIRA API
        jira_issue: The JIRA issue object or issue key to check transitions for

    Returns:
        None. Prints transition details to standard output.

    Example:
        >>> list_issue_transitions(jira, 'PROJECT-123')
        Transition Id: 11  Name: To Do
        Transition Id: 21  Name: In Progress
        Transition Id: 31  Name: Done
    """
    transitions = jira_connection.transitions(jira_issue)
    for transition in transitions:
        print(f'Transition Id: {transition['id']}  Name: {transition['name']}')

def assign_user(jira_connection, jira_issue, jira_user):
    """
    Assigns a Jira issue to a specific user.

    Args:
        jira_connection: The JIRA connection object used to interact with JIRA API.
        jira_issue: The JIRA issue key or object to be assigned.
        jira_user: The username or account ID of the user to assign the issue to.

    Returns:
        The response from the JIRA API assignment operation.

    Raises:
        Exception: If the assignment fails, either due to JIRA API error or other issues.
            The exception message includes details about the failure, including the issue key
            and target user, and preserves the original error context.
    """
    try:
        return jira_connection.assign_issue(jira_issue, jira_user)
    except JIRAError as jex:
        raise Exception(f'Failed to assign issue {jira_issue} to user {jira_user}: {jex.text}') from jex
    except Exception as e:
        raise Exception(f'Failed to assign issue {jira_issue} to user {jira_user}') from e

def submit_jsm_form(summary, assignment_team, audit_year, service_desk_id, request_type_id, jira_url, username, api_token):
    """
    Submits a Jira Service Management form with the specified fields using the Atlassian Python API.

    Args:
        summary (str): The summary of the request.
        assignment_team (str): The team to assign the request to.
        audit_year (int): The audit year.
        service_desk_id (str): The ID of the service desk.
        request_type_id (str): The ID of the request type.
        jira_url (str): The Jira Service Management API base URL.
        username (str): The username for authentication.
        api_token (str): The API token for authentication.

    Returns:
        dict: The response from the Jira API.
    """
    service_desk = ServiceDesk(
        url=jira_url,
        username=username,
        password=api_token
    )

    fields = {
        "summary": summary,
        "customfield_assignment_team": assignment_team,
        "customfield_audit_year": audit_year
    }

    response = service_desk.create_customer_request(
        service_desk_id=service_desk_id,
        request_type_id=request_type_id,
        request_fields=fields
    )
    return response

def list_jsm_form_fields(service_desk_id, request_type_id, jira_url, username, api_token):
    """
    Lists the fields for a specific Jira Service Management form.

    Args:
        service_desk_id (str): The ID of the service desk.
        request_type_id (str): The ID of the request type.
        jira_url (str): The Jira Service Management API base URL.
        username (str): The username for authentication.
        api_token (str): The API token for authentication.

    Returns:
        dict: The fields for the specified request type.
    """
    service_desk = ServiceDesk(
        url=jira_url,
        username=username,
        password=api_token
    )

    response = service_desk.get_request_type_fields(
        service_desk_id=service_desk_id,
        request_type_id=request_type_id
    )
    return response

def jira_response_check(jira_response):
    """
    Check for errors in Jira API response and raise appropriate exceptions.

    Args:
        jira_response: Response object from Jira API call. Can be None or a dictionary containing
                      potential error messages.

    Raises:
        Exception: If response contains error messages in 'errorMessages' or 'errors' fields
        ValueError: If response cannot be parsed properly

    Returns:
        None if response is None or no errors are found
    """
    try:
        if jira_response == None :
            return
        elif 'errorMessages' in jira_response and jira_response['errorMessages'].len(): 
            raise Exception(jira_response['errorMessages'])
        elif 'errors' in jira_response and jira_response['errors'].len(): 
            raise Exception(jira_response['errors'])
    except:
        raise ValueError("Unable to parse Jira Response")

def EnsureBase64Decode(s):
    try:
        return base64.b64decode(s).decode()
    except:
        return s


def main():
    parser = argparse.ArgumentParser(description='JIRA Extensions')
    parser.add_argument('-s','--jira_server', type=str_url, default=os.environ.get("JIRA_SERVER"), help='Jira server URL')
    parser.add_argument('-u','--jira_user', type=validate_email, default=os.environ.get("JIRA_USER"), help='Jira user')
    parser.add_argument('-t', '--jira_token', type=str_alnum_eq, default=os.environ.get("JIRA_TOKEN"), help='Jira personal access token (API Token)')

    parser.add_argument('-issue', type=str_alnum, help="Jira issue for operation")
    parser.add_argument('-comment', type=str_string_without_markup, help="String to add as comment to the issue")

    parser.add_argument('-assign', type=str, help="the user to assign the issue to. None will set it to unassigned. -1 will set it to Automatic.")

    parser.add_argument('--list_all_custom_fields', action='store_true', help='Flag to list all custom fields.')
    parser.add_argument('--list_issue_fields', action='store_true', help='Flag to list custom fields for a given issue')
    parser.add_argument('--list_issue_transitions', action='store_true', help='Flag to list transitions for a given issue')
    parser.add_argument('-transition', type=str_alnum, help="Jira issue transition to apply")

    parser.add_argument('--field_to_set', type=str_alnum, help="Jira issue field to set")
    parser.add_argument('--field_value', type=str_alnum, help="Jira issue field value to set")
    parser.add_argument('--field_value_id', type=str_alnum, help="Jira issue field value id to set")


    parser.add_argument('-q', '--jql', type=str_base64_decoded, help='JQL Query Language (JQL) query. Can be Base64 encoded or enclosed in double quotes with single quotes in the query')

    parser.add_argument('-f', '--file_name', type=str_filename, default="jira_output.csv", help='Name of the CSV file to save the data. Default is jira_output.csv')
    
    parser.add_argument('--fields', nargs='+', default=["summary","description","status","assignee","reporter","created"], help='Fields to be returned from Jira. Default is ["key","summary","status","assignee","reporter","created","ip_address"]')
    parser.add_argument('--page_size', type=int, default=100, help='Page size for the Jira query. Default is 100')
    parser.add_argument('--localserver', action='store_true', help='Flag to indicate a self-signed certificate is being used. Causes ignoring of certificate.')
    parser.add_argument('--overwrite', action='store_true', help='Flag to indicate if the file should be overwritten if it exists.')
    parser.add_argument('--expand_fields', nargs='+', help='Fields to expand in the Jira query. Default is None')

    parser.add_argument('--debug', action='store_true', help='Allow debug output and expanded exception display.')

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
        logging.debug('Debug logging set')

    if not args.jira_server:
        print("Jira server must be specified via parameter or JIRA_SERVER environment variable.", os.environ.get("JIRA_SERVER"))
        parser.print_help()
        return
    
    if not args.jira_user:
        print("Jira user must be specified via parameter or JIRA_USER environment variable")
        parser.print_help()
        return
    
    if not args.jira_token:
        print("Jira token must be specified via parameter or JIRA_TOKEN environment variable")
        parser.print_help()
        return
    
    try:
    
        jira_connection = get_jira_connection(args.jira_server, args.jira_user, args.jira_token, args.localserver)
        expand_fields = "".join(args.expand_fields, ",") if args.expand_fields else None
        
        if args.list_all_custom_fields:
            list_issue_fields(jira_connection)
            return
        
        if args.list_issue_fields and args.issue:
            if args.field_to_set:
                update_field_value(jira_connection, args.issue, args.field_to_set, args.field_value, args.field_value_id)
                print('updated')
            else:
                list_issue_fields(jira_connection, args.issue)
                print('done listing')
            return

        if args.list_issue_transitions and args.issue:
            list_issue_transitions(jira_connection, args.issue)
            print('done listing')
            return

        if args.jql:
            download_issue_data(
                args.jql,
                args.fields, 
                args.file_name,
                args.page_size,
                expand_fields,
                jira_connection=jira_connection,      
                localserver=args.localserver,
                overwrite_existing=args.overwrite)
            print("Done downloading.")
            return

        if args.assign and args.issue:
            jira_result = assign_user(jira_connection, args.issue, args.assign)
            print(f'Assigned issue: {args.issue} to {args.assign} :', 'success' if jira_result else 'fail')

        if args.transition and args.issue:
            jira_result = jira_set_issue_status(args.issue, args.transition, args.comment, jira_connection=jira_connection)
            jira_response_check(jira_result)
            print(f'Set issue transition: {args.issue} to {args.transition}: ')
            return 

        if args.comment and args.issue:
            jira_add_issue_comment(args.issue, args.comment, jira_connection=jira_connection) 
            print(f'Added comment: {args.issue} to {args.comment}')

        return
    
    except JIRAError as jex:
        if args.debug:
            logging.exception("Failed Jira Operation")
        else:
            print(f'Error: {jex.text}')
    except Exception as e:
        if args.debug:
            logging.exception("Failed Operation")
        else:
            print(f'Error {e}')

    exit(1)

if __name__ == '__main__':
    main()

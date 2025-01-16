import argparse
import os
import base64
import warnings
from jira import JIRA, JIRAError
import csv
import logging
import pprint

def download_issue_data(jql, fields=["summary","assignee","created"], file_name="jira_output.csv", page_size=100, expand_fields=None, jira_connection=None, jira_srver=None, jira_token=None, jira_user=None, localserver=False, overwrite_existing=True):
    """
    Downloads issue data from Jira based on the provided JQL query and saves it in a CSV file.

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
        jira_connection = get_jira_connection(jira_srver, jira_user, jira_token, localserver)
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
    Writes the Jira issues data to a CSV file.

    Args:
        issues (list): List of Jira issues.
        fields (list): List of fields to include in the CSV.
        file_name (str): Name of the CSV file.
        csv_header (bool): Flag to indicate if the CSV file should write a header row.
    """

    with open(file_name, mode='a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["Issue key", "Issue id"] + fields)
        
        if csv_header:
            writer.writeheader()
        
        for issue in issues:
            issueInfo = {"Issue key": issue.key, "Issue id": issue.id}
            row = {field: issue.fields.__dict__.get(field) for field in fields}
            # make sure key and id are the first columns
            row = {**issueInfo, **row}
            writer.writerow(row)

def get_jira_connection(jira_srver, jira_user, jira_token, localserver=False):
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

    logging.info(f"Connecting to Jira server {jira_srver}")

    try:
        return JIRA(options, max_retries=0, basic_auth=basicAuth)
    except Exception as ex:
        logging.info(f"Error connecting to Jira server: {ex}")
        return

def jira_set_issue_status(jira_issue, jira_status, comment=None, jira_server=None, jira_user=None, jira_token=None, jira_connection=None, localserver=False, fields=None):

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
    issue = jira_connection.issue(jira_issue) #, field=field_to_set
    if field_value_id:
        logging.debug('setting value by id')
        return issue.update(fields={ field_to_set : {'id': field_value_id} })
    elif field_value_name:
        logging.debug('setting value by name')
        return issue.update(fields={ field_to_set : {'value': field_value_name} })

def list_issue_fields(jira_connection, jira_issue):
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
    transitions = jira_connection.transitions(jira_issue)
    for transition in transitions:
        print(f'Transition Id: {transition['id']}  Name: {transition['name']}')

def assign_user(jira_connection, jira_issue, jira_user):
    try:
        return jira_connection.assign_issue(jira_issue, jira_user)
    except JIRAError as jex:
        raise Exception(f'Failed to assign issue {jira_issue} to user {jira_user}: {jex.text}') from jex
    except Exception as e:
        raise Exception(f'Failed to assign issue {jira_issue} to user {jira_user}') from e

def jira_response_check(jira_response):
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
    parser.add_argument('-s','--jira_server', default=os.environ.get("JIRA_SERVER"), help='Jira server URL')
    parser.add_argument('-u','--jira_user', default=os.environ.get("JIRA_USER"), help='Jira user')
    parser.add_argument('-t', '--jira_token', default=os.environ.get("JIRA_TOKEN"), help='Jira personal access token (API Token)')

    parser.add_argument('-issue', type=str, help="Jira issue for operation")
    parser.add_argument('-comment', type=str, help="String to add as comment to the issue")

    parser.add_argument('-assign', type=str, help="the user to assign the issue to. None will set it to unassigned. -1 will set it to Automatic.")

    parser.add_argument('--list_all_custom_fields', action='store_true', help='Flag to list all custom fields.')
    parser.add_argument('--list_issue_fields', action='store_true', help='Flag to list custom fields for a given issue')
    parser.add_argument('--list_issue_transitions', action='store_true', help='Flag to list transitions for a given issue')
    parser.add_argument('-transition', type=str, help="Jira issue transition to apply")

    parser.add_argument('--field_to_set', type=str, help="Jira issue field to set")
    parser.add_argument('--field_value', type=str, help="Jira issue field value to set")
    parser.add_argument('--field_value_id', type=str, help="Jira issue field value id to set")


    parser.add_argument('-q', '--jql', help='JQL Query Language (JQL) query. Can be Base64 encoded or encolsed in double quotes with single quotes in the query')

    parser.add_argument('-f', '--file_name', default="jira_output.csv", help='Name of the CSV file to save the data. Default is jira_output.csv')
    
    parser.add_argument('--fields', nargs='+', default=["summary","description","status","assignee","reporter","created"], help='Fields to be returned from Jira. Default is ["key","summary","status","assignee","reporter","created","ip_address"]')
    parser.add_argument('--page_size', type=int, default=100, help='Page size for the Jira query. Default is 100')
    parser.add_argument('--localserver', action='store_true', help='Flag to indicate a self-signed certificate is being used. Causes ignoreing of certificate.')
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
            jql = EnsureBase64Decode(args.jql)
            download_issue_data(
                jql,
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
            print(f'Assiged issue: {args.issue} to {args.assign} :', 'success' if jira_result else 'fail')

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

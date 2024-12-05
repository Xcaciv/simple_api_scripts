import requests
from graphql import build_client_schema, get_introspection_query, print_schema

def download_introspection_schema(endpoint_url, headers=None):
    # Get the introspection query
    introspection_query = get_introspection_query()

    # Send the introspection query to the GraphQL endpoint
    response = requests.post(endpoint_url, json={'query': introspection_query}, headers=headers)

    # Raise an exception if the request was unsuccessful
    response.raise_for_status()

    # Get the introspection result
    introspection_result = response.json()

    return introspection_result

def display_readable_schema(introspection_result):
    # Build the schema from the introspection result
    schema = build_client_schema(introspection_result['data'])

    # Print the schema in a readable format
    print(print_schema(schema))

if __name__ == "__main__":
    # Define the GraphQL endpoint URL
    endpoint_url = 'https://your-graphql-endpoint.com/graphql'

    # Optional: Define any headers required for the request
    headers = {
        'Authorization': 'Bearer YOUR_ACCESS_TOKEN'
    }

    # Download the introspection schema
    introspection_result = download_introspection_schema(endpoint_url, headers)

    # Display the readable schema
    display_readable_schema(introspection_result)
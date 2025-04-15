from argparse import ArgumentError
import base64
import re

def str_string_without_markup(value):
    """
    Remove any HTML-like markup from the input string and return a cleaned version.

    This function uses a regular expression to remove any substrings that match
    HTML tags (i.e., anything between '<' and '>'). It then splits the cleaned
    string into words and joins them back together with a single space, ensuring
    that any extra whitespace is removed.

    Args:
        value (str): The input string that may contain HTML-like markup.

    Returns:
        str: The cleaned string with HTML-like markup removed and extra whitespace normalized.
    """
    return ' '.join(re.sub(r'<[^>]*>', '', value).split())

def str_alnum(value):
    """
    Validates that the input string contains only alphanumeric characters, 
    spaces, underscores, or hyphens.

    Args:
        value (str): The input string to be validated.

    Returns:
        str: A string containing only the valid characters from the input.
    """

    pattern = re.compile(r'^[a-zA-Z0-9_- ]+$')
    return ''.join(pattern.findall(value))

def str_alnum_eq(value):
    """
    Validates and filters a string to contain only alphanumeric characters, equals sign, underscore and hyphen.
    Args:
        value (str): The string to validate and filter.
    Returns:
        str: A filtered string containing only allowed characters (alphanumeric, =, _, -).
            Returns an empty string if no valid characters are found.
    Example:
        >>> validate_alnum_eq("Hello123=_-")
        'Hello123=_-'
        >>> validate_alnum_eq("Hello@#$%")
        'Hello'
    """

    pattern = re.compile(r'^[a-zA-Z0-9=_-]+$')
    return ''.join(pattern.findall(value))

def validate_ip_address_list(value):
    """
    Validates a string containing a list of IP addresses.

    The function checks if the input string matches the pattern of valid IP addresses.
    Each IP address can optionally be followed by a subnet mask (e.g., /24).
    IP addresses can be separated by spaces or commas.

    Args:
        value (str): The input string containing the list of IP addresses.

    Returns:
        str: The validated input string.

    Raises:
        ArgumentError: If the input string does not match the pattern of valid IP addresses.
    """
    pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?[\s,]*$')
    if not pattern.match(value):
        raise ArgumentError(f"Invalid list of IP addresses in input: {value}")
    return value

def str_base64_decoded(value):
    """
    Decodes a base64 encoded string.

    This function attempts to decode the provided base64 encoded string. If the decoding
    is successful, it returns the decoded string. If the decoding fails (e.g., if the input
    is not a valid base64 encoded string), it returns the original input value.

    Args:
        value (str): The base64 encoded string to decode.

    Returns:
        str: The decoded string if the input is a valid base64 encoded string, otherwise
        the original input value.
    """
    try:
        return base64.b64decode(value).decode()
    except:
        return value
    
def str_base64_encoded(value):
    """
    Validates and encodes a given string value to Base64.
    Args:
        value (str): The string value to be encoded.
    Returns:
        str: The Base64 encoded string if encoding is successful, 
             otherwise returns the original string.
    """

    try:
        return base64.b64encode(value.encode()).decode()
    except:
        return value
    
def validate_email(value):
    """
    Validates if the provided value is a valid email address.

    Args:
        value (str): The email address to validate.

    Returns:
        str: The validated email address.

    Raises:
        ArgumentError: If the email address is not valid.
    """
    pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    if not pattern.match(value):
        raise ArgumentError(f"Invalid email address in input: {value}")
    return value

def str_url(value):
    """
    Validates if the given value is a properly formatted URL.

    Args:
        value (str): The URL string to validate.

    Returns:
        str: The validated URL string.

    Raises:
        ArgumentError: If the URL is not valid.
    """
    pattern = re.compile(r'^https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[\w\-\d]+')
    if not pattern.match(value):
        raise ArgumentError(f"Invalid URL in input: {value}")
    return value

def str_url_with_trailing_slash(value):
    """
    Validates a URL and ensures it ends with a trailing slash.

    This function first validates the given URL using the `validate_url` function.
    If the URL does not end with a trailing slash, it appends one.

    Args:
        value (str): The URL to be validated and modified.

    Returns:
        str: The validated URL with a trailing slash.
    """
    str_url(value)
    if not value.endswith('/'):
        value += '/'
    return value

def str_filename(value):
    """
    Validates a string to contain only valid characters for a filename.

    Args:
        value (str): The string to validate.

    Returns:
        str: A filtered string containing only valid characters for a filename.
    """
    pattern = re.compile(r'^[a-zA-Z0-9 _.-]+$')
    return ''.join(pattern.findall(value))
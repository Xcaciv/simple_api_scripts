import csv
from tabulate import tabulate

def append_csv_row(file_path, row):
    with open(file_path, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(row)

def search_csv_column(file_path, column_index, search_value):
    """
    Searches for a specific value in a CSV file column.
    Args:
        file_path (str): The path to the CSV file.
        column_index (int): The index of the column to search in.
        search_value: The value to search for.
    Returns:
        dict: A dictionary containing the header values as keys and the corresponding row values as values.
              Returns None if the search value is not found.
    """
    with open(file_path, mode='r', newline='') as csv_file:
        csv_reader = csv.reader(csv_file)
        # read header row
        headers = next(csv_reader)

        for row in csv_reader:
            if row[column_index] == search_value:
                # combine header and row to return a dictionary
                return dict(zip(headers, row))
            
    return None

def search_csv_column_in_start(file_path, column_index, search_value):
    """
    Searches for a specific value in a CSV file column.
    Args:
        file_path (str): The path to the CSV file.
        column_index (int): The index of the column to search in.
        search_value: The value to search for.
    Returns:
        dict: A dictionary containing the header values as keys and the corresponding row values as values.
              Returns None if the search value is not found.
    """
    with open(file_path, mode='r', newline='') as csv_file:
        csv_reader = csv.reader(csv_file)
        # read header row
        headers = next(csv_reader)

        for row in csv_reader:
            # check if search value starts with the column value
            if search_value.startswith(row[column_index]):            
                # combine header and row to return a dictionary
                return dict(zip(headers, row))
            
    return None

def search_csv_column_starts_with(file_path, column_index, search_value):
    """
    Searches for a specific value in a CSV file column.
    Args:
        file_path (str): The path to the CSV file.
        column_index (int): The index of the column to search in.
        search_value: The value to search for.
    Returns:
        dict: A dictionary containing the header values as keys and the corresponding row values as values.
              Returns None if the search value is not found.
    """
    with open(file_path, mode='r', newline='') as csv_file:
        csv_reader = csv.reader(csv_file)
        # read header row
        headers = next(csv_reader)

        for row in csv_reader:
            # check if search value starts with the column value
            if row[column_index].startswith(search_value):            
                # combine header and row to return a dictionary
                return dict(zip(headers, row))
            
    return None

def extract_unique_values(file_path, column_index):
    """
    Extracts unique values from a specific column in a CSV file.
    Args:
        file_path (str): The path to the CSV file.
        column_index (int): The index of the column to extract unique values from.
        chunk_size (int): The number of rows to read at a time.
    Returns:
        set: A set of unique values from the specified column.
    """
    unique_values = set()
    with open(file_path, mode='r', newline='') as csv_file:
        csv_reader = csv.reader(csv_file)
        # skip header row
        next(csv_reader)

        for row in csv_reader:
            unique_values.add(row[column_index])

    return list(unique_values)


def csv_to_dict(file_path, key_column):
    """
    Converts a CSV file to a dictionary.
    Args:
        file_path (str): The path to the CSV file.
        key_column (str): The column to use as the key in the dictionary.
    Returns:    
        dict: A dictionary with the key_column values as keys and the corresponding row values as values.
    """
    data = {}
    with open(file_path, mode='r', newline='') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        # read header row
        for row in csv_reader:
            # combine header and row to return a dictionary
            data[row[key_column]] = row

    return data

def csv_dict_iterate(file_path):
    with open(file_path, mode='r', newline='') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        # read header row
        for row in csv_reader:
            # combine header and row to return a dictionary
            yield row
    
    
def print_csv_table(file_path):
    table = tabulate(csv_dict_iterate(file_path),
                     headers="keys",
                     tablefmt="psql")
    print(table)
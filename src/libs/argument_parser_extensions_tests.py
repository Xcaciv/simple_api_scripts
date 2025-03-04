from unittest import TestCase
from argument_parser_extensions import validate_ip_address_list
from argparse import ArgumentError

class TestValidateIpAddressList(TestCase):

    def test_single_ip(self):
        result = validate_ip_address_list("192.168.1.1")
        self.assertEqual(result, "192.168.1.1")

    def test_multiple_ips_comma_separated(self):
        result = validate_ip_address_list("192.168.1.1,10.0.0.1")
        self.assertEqual(result, "192.168.1.1,10.0.0.1")

    def test_multiple_ips_space_separated(self):
        result = validate_ip_address_list("192.168.1.1 10.0.0.1")
        self.assertEqual(result, "192.168.1.1,10.0.0.1")

    def test_ip_with_subnet(self):
        result = validate_ip_address_list("192.168.1.1/24")
        self.assertEqual(result, "192.168.1.1/24")
    
    def test_multiple_ip_with_subnet(self):
        result = validate_ip_address_list("192.168.1.1,192.168.1.1/24, 192.168.1.1,10.0.0.1/16")
        self.assertEqual(result, "192.168.1.1,192.168.1.1/24,192.168.1.1,10.0.0.1/16")

    def test_invalid_ip(self):
        with self.assertRaises(ArgumentError):
            validate_ip_address_list("256.256.256.256")

    def test_invalid_format(self):
        with self.assertRaises(ArgumentError):
            validate_ip_address_list("not an ip")

    def test_empty_string(self):
        with self.assertRaises(ArgumentError):
            validate_ip_address_list("")

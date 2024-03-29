import unittest
from main import validate_json, InvalidJsonFormatException

class TestValidateJson(unittest.TestCase):
    def test_valid_json(self):
        json_string = '''
        {
            "PolicyName": "root",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "IamListAccess",
                        "Effect": "Allow",
                        "Action": [
                            "iam:ListRoles",
                            "iam:ListUsers"
                        ],
                        "Resource": "arn:aws:iam::123456789012:role/*"
                    }
                ]
            }
        }
        '''
        self.assertTrue(validate_json(json_string))

    def test_invalid_json(self):
        invalid_json_string = 'invalid_json'
        with self.assertRaises(InvalidJsonFormatException):
            validate_json(invalid_json_string)

    def test_invalid_json_format(self):
        invalid_json_string = '''
        {
            "PolicyName": "root",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "IamListAccess",
                        "Effect": "Allow",
                        "Action": [
                            "iam:ListRoles",
                            "iam:ListUsers"
                        ],
                        "Resource": "*"
                    }
                ]
            }
        '''
        with self.assertRaises(InvalidJsonFormatException):
            validate_json(invalid_json_string)

    def test_resource_contains_single_asterisk(self):
        json_string = '''
        {
            "PolicyName": "root",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "IamListAccess",
                        "Effect": "Allow",
                        "Action": [
                            "iam:ListRoles",
                            "iam:ListUsers"
                        ],
                        "Resource": "*"
                    }
                ]
            }
        }
        '''
        self.assertFalse(validate_json(json_string))

if __name__ == '__main__':
    unittest.main()
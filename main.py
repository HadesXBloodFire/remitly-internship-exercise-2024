import json


class AWSIAMRolePolicy:
    def __init__(self, PolicyName, PolicyDocument):
        self.PolicyName = PolicyName
        self.PolicyDocument = PolicyDocument


class PolicyDocument:
    def __init__(self, Version, Statement):
        self.Version = Version
        self.Statement = Statement


class Statement:
    def __init__(self, Sid, Effect, Action, Resource):
        self.Sid = Sid
        self.Effect = Effect
        self.Action = Action
        self.Resource = Resource


class InvalidJsonFormatException(Exception):
    pass


def read_json_from_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()


def validate_json(json_string):
    try:
        data = json.loads(json_string)
        policy = AWSIAMRolePolicy(data['PolicyName'], PolicyDocument(data['PolicyDocument']['Version'], []))

        for statement_data in data['PolicyDocument']['Statement']:
            statement = Statement(statement_data['Sid'], statement_data['Effect'], statement_data['Action'],
                                  statement_data['Resource'])
            policy.PolicyDocument.Statement.append(statement)
            if statement.Resource == "*":
                return False

        return True
    except (json.JSONDecodeError, KeyError) as e:
        raise InvalidJsonFormatException(f"Invalid JSON format: {str(e)}")


if __name__ == "__main__":
    try:
        json_file_path = 'data.json'
        json_string = read_json_from_file(json_file_path)
        is_valid = validate_json(json_string)
        print(is_valid)
    except FileNotFoundError as e:
        print(f"File not found: {str(e)}")
    except InvalidJsonFormatException as e:
        print(f"{str(e)}")
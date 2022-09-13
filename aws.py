import json
import boto3
from collections import OrderedDict
from aws_utils import run_aws_operation



# for region_name in region_names:
credentials = dict(access_key=AWS_IAM_KEY_ID, secret_key=AWS_IAM_ACCESS_KEY)
# client = boto3.client('iam', aws_access_key_id=AWS_IAM_KEY_ID,
#                       aws_secret_access_key=AWS_IAM_ACCESS_KEY)
regions = ['us-east-1', 'us-east-2']
operation_args = {}
# operation_args = {"Filters": [{'Name': 'instance-state-name', 'Values': ['running']}]}
for region in regions:
    db_response = run_aws_operation(credentials, 'dynamodb', 'list_tables', region_name=region,
                                response_key='TableNames')
    try:
        for table in db_response:
            operation_args.update(TableName=table)
            table_response = run_aws_operation(
                credentials, 'dynamodb', 'describe_continuous_backups', region_name=region,
                operation_args=operation_args)
            print(table_response)
    except Exception as e:
        if "TableNotFoundException" in str(e):
            continue
        else:
            raise Exception(str(e))

# response = client.list_buckets()
# for bucket in response['Buckets']:
#     print(bucket['Name'])
# handler = dict(Filters=[
#     {
#         'Name': 'ip-permission.from-port',
#         'Values': [
#             '53',
#         ]
#     },
#     {
#         'Name': 'ip-permission.to-port',
#         'Values': [
#             '53',
#         ]
#     },
#     {
#         'Name': 'ip-permission.cidr',
#         'Values': [
#             '0.0.0.0',
#         ]
#     },
# ])
# handler_two = [
#     {
#         'Name': 'ip-permission.from-port',
#         'Values': [
#             ''
#         ]
#     },
#     {
#         'Name': 'ip-permission.to-port',
#         'Values': [
#             '53'
#         ]
#     },
#     {
#         'Name': 'ip-permission.cidr',
#         'Values': [
#             '0.0.0.0/0'
#         ]
#     }
# ]
# response = client.describe_security_groups(Filters=handler_two)
#
# for r in response['SecurityGroups']:
#     print(r['GroupName'])

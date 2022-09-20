# Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.

from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType
from rdklib.util.evaluations import clean_up_old_evaluations
from urllib3.util.retry import Retry
from urllib3.util import parse_url
import urllib3
import boto3
import os
import sys

# Disabling InsecureRequestWarning, this rule is not checking if certificates are valid. Another rule will perform that
# Check.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::EC2::Instance'

# Set to True to get the lambda to assume the Role attached on the Config Service (useful for cross-account).
ASSUME_ROLE_MODE = True

# Other parameters (no change needed)
CONFIG_ROLE_TIMEOUT_SECONDS = 900

# Port Ec2 security groups are being checked for
TARGET_PORT = 80

# Used to determine how to establish connection with AWS. If local, then connection will be made with boto3
ENV = os.environ.get('ENV')


#################################
# Supporting Functions for Rule #
#################################
def fetch_all_items(method, response_key, next_token_key, **kwargs):
    """
    client: The boto3 client
    method: The boto3 method to be fetched (e.g. ecs_client.list_clusters)
    kwargs: The parameter name and value for a given boto3 method (e.g. ecs_client.list_services(cluster=clusterArn))
    """
    if kwargs:
        response = method(**kwargs)
    else:
        response = method()

    items = response[response_key]
    next_token = response.get(next_token_key)
    while next_token:
        token = {next_token_key: next_token}
        response = method(**token, **kwargs)
        items = items + response[response_key]
        next_token = response.get(next_token_key)

    return items


def ec2_compliant_check(endpoint, port):
    """
    Checks if ec2 instance is compliant
    Rules:
        Compliant if:
            Redirect to port 443
    endpoint: endpoint of the ec2 instance
    """
    try:
        # The certificate is not being verified, only checking if https is enabled, hence "cert_reqs=CERT_NONE"
        sess = urllib3.PoolManager(cert_reqs='CERT_NONE')
        retries = Retry(total=3,
                        backoff_factor=0.1,
                        redirect=5,
                        status_forcelist=[500, 502, 503, 504])
        response = sess.request('GET', f'http://{endpoint}:{port}', retries=retries, timeout=15.0)

        if response.status == 200:
            # Check the response's history to see the redirect history
            for redirect in response.retries.history:
                if parse_url(redirect.url).scheme == 'https':
                    return True
        return False
    except urllib3.exceptions.HTTPError as e:
        print(e)
        return False
    except:
        print("Unexpected error:", sys.exc_info()[0])
        return False


def is_traffic_allowed(inbound_rule, port):
    """
    Checks if the inbound rule allows traffic through the specified port
    :param inbound_rule: The security group's inbound rule being evaluated
    :param port: the targeted port
    :return: boolean
    """
    return inbound_rule['IpProtocol'] == '-1' or (inbound_rule['FromPort'] <= port <= inbound_rule['ToPort'])


#############
# Main Code #
#############
class GPSEC_EC2_HTTPS_REDIRECT(ConfigRule):
    def evaluate_periodic(self, event, client_factory, valid_rule_parameters):
        """Form the evaluation(s) to be return to Config Rules

        Return either:
        None -- when no result needs to be displayed
        a list of Evaluation -- a list of evaluation object , built by Evaluation()

        Keyword arguments:
        event -- the event variable given in the lambda handler
        client_factory -- ClientFactory object to be used in this rule. It is defined in RDKLib.
        configuration_item -- the configurationItem dictionary in the invokingEvent
        valid_rule_parameters -- the output of the evaluate_parameters() representing validated parameters of the Config Rule

        Advanced Notes:
        1 -- if a resource is deleted and generate a configuration change with ResourceDeleted status, the Boilerplate code will put a NOT_APPLICABLE on this resource automatically.
        2 -- if a None or a list of dictionary is returned, the old evaluation(s) which are not returned in the new evaluation list are returned as NOT_APPLICABLE by the Boilerplate code
        3 -- if None or an empty string, list or dict is returned, the Boilerplate code will put a "shadow" evaluation to feedback that the evaluation took place properly
        """

        # Connect to EC2
        if ENV == 'local':
            session = boto3.session.Session(profile_name=os.environ.get('AWS_PROFILE'))
            ec2_service = session.client('ec2', region_name=os.environ.get('AWS_REGION'))
        else:
            ec2_service = client_factory.build_client('ec2')

        evaluations = []

        # Annotations
        non_compliant_annotation = "NON_COMPLIANT: Port 80 should either be closed or redirect all traffic to port 443"
        compliant_annotation_1 = "COMPLIANT: Traffic is redirected to port 443"
        compliant_annotation_2 = "COMPLIANT: Port 80 is closed"
        not_applicable_annotation = "NOT_APPLICABLE: EC2 is not running"

        # List that will store security groups with port 80 open
        target_sec_groups = []

        # Get a list of all security groups in account that have port 80 open
        sec_groups = fetch_all_items(ec2_service.describe_security_groups, 'SecurityGroups', 'NextToken')
        for sec_group in sec_groups:
            for inbound_rule in sec_group['IpPermissions']:
                if is_traffic_allowed(inbound_rule, TARGET_PORT):
                    target_sec_groups.append(sec_group['GroupId'])

        # Get a list of all EC2 in account
        ec2_instances = fetch_all_items(ec2_service.describe_instances, 'Reservations', 'NextToken')
        for item in ec2_instances:
            for instance in item['Instances']:

                instance_id = instance['InstanceId']
                if instance['State']['Name'] == 'running':

                    compliant_type = ComplianceType.NON_COMPLIANT
                    annotation = non_compliant_annotation
                    continue_check = True

                    # For each Ec2, iterate its security groups until one that's not compliant is found or all have
                    # been processed
                    for sec_group in instance['SecurityGroups']:

                        if continue_check:
                            sec_group_id = sec_group['GroupId']

                            # Check if the security group is part of the groups we're targeting
                            if sec_group_id in target_sec_groups:
                                print(f'[INFO] Checking compliance for InstanceID {instance_id}, sec group {sec_group_id}')

                                endpoint = instance['PublicDnsName'] or instance['PrivateIpAddress']
                                if endpoint:
                                    is_compliant = ec2_compliant_check(endpoint, TARGET_PORT)
                                else:
                                    print(f'[WARNING] Invalid endpoint for InstanceID {instance_id}, sec group {sec_group_id}')
                                    is_compliant = False

                                annotation = compliant_annotation_1 if is_compliant else non_compliant_annotation
                            else:
                                is_compliant = True
                                annotation = compliant_annotation_2

                            compliant_type = ComplianceType.COMPLIANT if is_compliant else ComplianceType.NON_COMPLIANT
                            continue_check = is_compliant
                        else:
                            break

                else:
                    compliant_type = ComplianceType.NOT_APPLICABLE
                    annotation = not_applicable_annotation

                evaluations.append(
                    Evaluation(compliant_type, instance_id, resourceType=DEFAULT_RESOURCE_TYPE, annotation=annotation))

        # If there are results return the evaluations
        #if evaluations:
        if "test" not in event.keys():
            latest_eval = [i.get_json() for i in evaluations]
            clean_up_old_evaluations(event, client_factory, latest_eval)
        return evaluations
        # if there are no results, return "NOT_APPLICABLE"
        #else:
        #    return []
        #return evaluations


def lambda_handler(event, context):
    my_rule = GPSEC_EC2_HTTPS_REDIRECT()
    evaluator = Evaluator(my_rule, DEFAULT_RESOURCE_TYPE)
    return evaluator.handle(event, context)

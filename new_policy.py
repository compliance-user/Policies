    def aws_vpc_flow_logs_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    vpc_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_vpcs',
                        region_name=region,
                        response_key='Vpcs')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                vpc_ids = [x.get('VpcId', 'NA') for x in vpc_response]
                for vpc_id in vpc_ids:
                    evaluated_resources += 1
                    operation_args = {'Filters': [
                        {
                            'Name': 'resource-id',
                            'Values': [vpc_id]
                        }
                    ]}
                    vpc_flow_log = run_aws_operation(
                        credentials, 'ec2', 'describe_flow_logs', operation_args,
                        region_name=region,
                        response_key='FlowLogs')
                    if not vpc_flow_log.get('FlowLogs'):
                        output.append(
                            OrderedDict(
                                ResourceId=vpc_id,
                                ResourceName=vpc_id,
                                ResourceType='EC2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

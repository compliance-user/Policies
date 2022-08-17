    def aws_ec2_check_disks_are_encrypted(self, **kwargs):
        try:
            output = list()
            evaluated_resources = 0
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_volumes',
                        region_name=region,
                        response_key='Volumes')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for volume in ec2_response:
                    evaluated_resources += 1
                    if not volume.get('Encrypted'):
                        output.append(
                            OrderedDict(
                                ResourceId=volume.get('VolumeId', ''),
                                ResourceName=volume.get('VolumeId', ''),
                                ResourceType='EC2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

"""
Install Before You Use
- AWSCLI (for your API Key Setup)
- Python 3.x, Developed at 3.9.1
- boto3 1.17.101
"""

import boto3
import json
import pprint

def cloudtrailGetSecurityGroupEvents():
    sgList = []
    sginfo = {}
    # CloudTrail Search Request API List, use for only Security Group Related
    requestType = ['AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress', 'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress', 'CreateSecurityGroup', 'DeleteSecurityGroup']
    # Loop Every API Type
    for reqType in requestType:
        response = boto3.client('cloudtrail').lookup_events(
            LookupAttributes=[
                {
                    # CloudTrail Search Options, Add Another Option if you need
                    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudtrail.html#CloudTrail.Client.lookup_events
                    'AttributeKey': 'EventName',
                    'AttributeValue': reqType
                }
            ])
        # Loop Every API Type -> Loop Every CloudTrail Events
        for event in response['Events']:
            result = json.loads(event['CloudTrailEvent'])
            if reqType == 'CreateSecurityGroup':
                sginfo['type'] = 'sg'
                sginfo['action'] = 'add'
                sginfo['eventId'] = result['eventID']
                sginfo['eventTime'] = result['eventTime']
                sginfo['userArn'] = result['userIdentity']['arn']
                sginfo['awsRegion'] = result['awsRegion']
                sginfo['requestIpAddress'] = result['sourceIPAddress']
                sginfo['securitygroupName'] = result['requestParameters']['groupName']
                sginfo['securitygroupId'] = result['responseElements']['groupId']
                sginfo['description'] = result['requestParameters']['groupDescription']
                sgList.append(sginfo)
                sginfo = {}
                continue
            if reqType == 'DeleteSecurityGroup':
                sginfo['type'] = 'sg'
                sginfo['action'] = 'del'
                sginfo['eventId'] = result['eventID']
                sginfo['eventTime'] = result['eventTime']
                sginfo['userArn'] = result['userIdentity']['arn']
                sginfo['awsRegion'] = result['awsRegion']
                sginfo['requestIpAddress'] = result['sourceIPAddress']
                sginfo['securitygroupId'] = result['requestParameters']['groupId']
                sgList.append(sginfo)
                sginfo = {}
                continue
            # Loop Every API Type -> Loop Every CloudTrail Events -> Loop Every Security Group Rules
            for rules in result['requestParameters']['ipPermissions']['items']:
                # Loop Every API Type -> Loop Every CloudTrail Events -> Loop Every Security Group Rules -> Loop Every Security Group Rule Lines
                for cidrs in rules['ipRanges']['items']:
                    if reqType == 'AuthorizeSecurityGroupIngress':
                        sginfo['type'] = 'ingress'
                        sginfo['action'] = 'add'
                    if reqType == 'AuthorizeSecurityGroupEgress':
                        sginfo['type'] = 'egress'
                        sginfo['action'] = 'add'
                    if reqType == 'RevokeSecurityGroupEgress':
                        sginfo['type'] = 'egress'
                        sginfo['action'] = 'del'
                    if reqType == 'RevokeSecurityGroupIngress':
                        sginfo['type'] = 'ingress'
                        sginfo['action'] = 'del'
                    sginfo['eventId'] = result['eventID']
                    sginfo['eventTime'] = result['eventTime']
                    sginfo['userArn'] = result['userIdentity']['arn']
                    sginfo['awsRegion'] = result['awsRegion']
                    sginfo['requestIpAddress'] = result['sourceIPAddress']
                    sginfo['securitygroupId'] = result['requestParameters']['groupId']
                    # Try except for deleted Security Group, example) User Change Security Gruop, and Remove Security Group
                    try:
                        sginfo['securitygroupName'] = boto3.resource('ec2').SecurityGroup(result['requestParameters']['groupId']).group_name
                    except Exception:
                        pass
                    # -1 means All Types(Any), Document:https://docs.aws.amazon.com/ko_kr/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group-ingress.html
                    if rules['ipProtocol'] == '-1':
                        sginfo['ipProtocol'] = '-1'
                        sginfo['fromPort'] = '-1'
                        sginfo['toPort'] = '-1'
                        sginfo['ip'] = cidrs['cidrIp']
                        if "description" in cidrs:
                            sginfo['description'] = cidrs['description']
                    else:
                        sginfo['ipProtocol'] = rules['ipProtocol']
                        sginfo['fromPort'] = rules['fromPort']
                        sginfo['toPort'] = rules['toPort']
                        sginfo['ip'] = cidrs['cidrIp']
                        if "description" in cidrs:
                            sginfo['description'] = cidrs['description']
                    # Append infomation to sgList
                    sgList.append(sginfo)
                    # reCreate sginfo dict for Save sgList
                    sginfo = {}
    return sgList
                
response = cloudtrailGetSecurityGroupEvents()
pprint.pprint(response, width=10, indent=4)

for i in response:
    print(i['type'],i['action'])
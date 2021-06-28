import boto3
import json
import pprint

def cloudtrailGetSecurityGroupEvents():
    sgList = []
    sginfo = {}
    requestType = ['AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress', 'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress', 'CreateSecurityGroup', 'DeleteSecurityGroup']
    for reqType in requestType:
        response = boto3.client('cloudtrail').lookup_events(
            LookupAttributes=[
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': reqType
                }
            ])
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
            for rules in result['requestParameters']['ipPermissions']['items']:
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
                    try:
                        sginfo['securitygroupName'] = boto3.resource('ec2').SecurityGroup(result['requestParameters']['groupId']).group_name
                    except Exception:
                        pass
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
                    sgList.append(sginfo)
                    sginfo = {}
    response = boto3.client('cloudtrail').lookup_events(
        LookupAttributes=[
            {
                'AttributeKey': 'EventName',
                'AttributeValue': 'CreateSecurityGroup'
            }
        ])
    for event in response['Events']:
        result = json.loads(event['CloudTrailEvent'])
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
    return sgList
                
response = cloudtrailGetSecurityGroupEvents()
pprint.pprint(response, width=10, indent=4)

for i in response:
    print(i['type'],i['action'])
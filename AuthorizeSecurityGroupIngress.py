import boto3
import pprint
import json

pp = pprint.PrettyPrinter(indent=4)
cloudtrail = boto3.client('cloudtrail')

response = cloudtrail.lookup_events(
    LookupAttributes=[
        {
            'AttributeKey': 'EventName',
            'AttributeValue': 'AuthorizeSecurityGroupIngress'
        }
    ]
)

print('----------Inbound Rules----------')
for event in response['Events']:
    result = json.loads(event['CloudTrailEvent'])
    print("CloudTrail Event ID :",result['eventID'])
    print('Event Time(UTC) :',result['eventTime'])
    print("User ARN :",result['userIdentity']['arn'])
    print('AWS Region :',result['awsRegion'],'/','Request Source IP :',result['sourceIPAddress'])
    print('SecurityGroup :',result['requestParameters']['groupId'],'/',boto3.resource('ec2').SecurityGroup(result['requestParameters']['groupId']).group_name)
    for rules in result['requestParameters']['ipPermissions']['items']:
      print("From IP {:18s} To Port {}-{}/{}".format(rules['ipRanges']['items'][0]['cidrIp'],rules['fromPort'],rules['toPort'],rules['ipProtocol']))  
    print('-------------------------')

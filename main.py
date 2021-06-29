"""
Install Before You Use
- AWSCLI (for your API Key Setup)
- Python 3.x, Developed at 3.9.1
- boto3 1.17.101
"""

from genericpath import exists
import boto3
import json
import pprint
import sqlite3

requestType = ['AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress', 'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress', 'CreateSecurityGroup', 'DeleteSecurityGroup']
dbFileLocation = 'aws-notify.db'

def cloudtrailGetSecurityGroupEvents():
    sgList = []
    sginfo = {}
    # CloudTrail Search Request API List, use for only Security Group Related
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

def addOnSqlite3(list):
    con = sqlite3.connect(dbFileLocation)
    cur = con.cursor()
    # Check DB Table Exists
    if not cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'").fetchone():
        # if DB Table Not Exists then Create Table
        cur.execute('''CREATE TABLE events(type TEXT, action TEXT, eventId TEXT, eventTime TEXT, userArn TEXT, awsRegion TEXT,  requestIpAddress TEXT, securitygroupId TEXT, securitygroupName TEXT, ip TEXT, fromPort INTEGER, toPort INTEGER, ipProtocol TEXT, description TEXT, notified INTEGER)''')      
    # Loop Every sgList(captured Event Lists)
    for sgList in list:
        # Check overlap eventId Exists
        if not cur.execute("SELECT eventId FROM events WHERE eventId = '{}'".format(sgList.get('eventId', 'NULL'))).fetchone():
            cur.execute("INSERT INTO events VALUES('{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')".format(
                sgList.get('type', 'NULL'),             sgList.get('action', 'NULL'),           sgList.get('eventId', 'NULL'), 
                sgList.get('eventTime', 'NULL'),        sgList.get('userArn', 'NULL'),          sgList.get('awsRegion', 'NULL'), 
                sgList.get('requestIpAddress', 'NULL'), sgList.get('securitygroupId', 'NULL'),  sgList.get('securitygroupName', 'NULL'), 
                sgList.get('ip', 'NULL'),               sgList.get('fromPort', 'NULL'),         sgList.get('toPort', 'NULL'), 
                sgList.get('ipProtocol', 'NULL'),       sgList.get('description', 'NULL'),      'NULL'))
    # Commit and Close 
    con.commit()
    con.close()


response = cloudtrailGetSecurityGroupEvents()
pprint.pprint(response, width=10, indent=4)
addOnSqlite3(response)
con = sqlite3.connect('aws-notify.db')
cur = con.cursor()
for row in cur.execute('SELECT * FROM events ORDER BY eventId'):
    print(row)
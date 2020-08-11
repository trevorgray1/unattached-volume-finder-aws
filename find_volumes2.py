#!/usr/bin/env python3
import boto3
from botocore.exceptions import ClientError
import datetime
import json
import csv
import sys

ec2client = boto3.client('ec2')
cloudtrail = boto3.client('cloudtrail')

try:
    response = cloudtrail.lookup_events(LookupAttributes=[
         {
             'AttributeKey': 'EventName',
             'AttributeValue': 'DetachVolume'
         },
     ],)
except ClientError as e:
    print(e)

keys = {}

format = "%a %b %d %H:%M:%S %Y"

for r in response['Events']:
    time = (r['EventTime'])
    format_time = ('{:%a %b %d %H:%M:%S %Y}'.format(time))
    keys.update({'Timestamp': format_time})
    for i in r['Resources']:
        resourcetype = (i['ResourceType'])
        resourcename = (i['ResourceName'])
        if resourcetype == 'AWS::EC2::Volume':
            keys.update({'Resourcetype': resourcetype})
            keys.update({'Resourcename': resourcename})
            print(keys)



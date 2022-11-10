#!/usr/bin/env python3

import socket
import json
import datetime
import boto3

class JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if type(obj) in [datetime.datetime, datetime.date]:
            return obj.isoformat()

hn = socket.gethostname()
pi = None
cli = boto3.client('ec2')
for res in cli.describe_instances().get('Reservations', []):
	for i in res.get('Instances', []):
		if i.get('InstanceId') == hn:
			print(json.dumps(i, cls=JsonEncoder, indent=4))
			pi = i.get('PublicIpAddress')
print(f"{hn} -> {pi}")

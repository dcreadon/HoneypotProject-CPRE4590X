import json
import base64
import gzip
import boto3
import os

# CONFIGURATION
# Best practice: Use an environment variable in Lambda for the bucket name
BUCKET_NAME = os.environ.get('BUCKET_NAME', 'cowrie-log-data') 
DATA_FILE = "ip_history.json"

s3 = boto3.client('s3')

def lambda_handler(event, context):
    # 1. Decode and decompress the CloudWatch logs
    cw_data = event['awslogs']['data']
    compressed = base64.b64decode(cw_data)
    log_data = json.loads(gzip.decompress(compressed))

    # 2. Retrieve existing IP history from S3
    try:
        response = s3.get_object(Bucket=BUCKET_NAME, Key=DATA_FILE)
        ip_history = json.loads(response['Body'].read().decode('utf-8'))
    except s3.exceptions.NoSuchKey:
        # If it's the first run, start with an empty dictionary
        ip_history = {}
    except Exception as e:
        print(f"Error retrieving file: {e}")
        ip_history = {}

    # 3. Process logs and map to Source IP
    for record in log_data['logEvents']:
        try:
            msg = json.loads(record['message'])
            ip_addr = msg.get('src_ip')
            
            if not ip_addr:
                continue

            # Initialize IP entry if it's the first time we've seen this attacker
            if ip_addr not in ip_history:
                ip_history[ip_addr] = []

            # Capture only the core data points you requested
            activity_entry = {
                "eventid": msg.get('eventid'),
                "input": msg.get('input', ""),
                "message": msg.get('message', ""),
                "timestamp": msg.get('timestamp')
            }
            
            # Append to this IP's history
            ip_history[ip_addr].append(activity_entry)
            
        except Exception:
            continue

    # 4. Save the updated JSON back to S3
    s3.put_object(
        Bucket=BUCKET_NAME, 
        Key=DATA_FILE, 
        Body=json.dumps(ip_history, indent=4), 
        ContentType='application/json'
    )

    return {"status": "IP-based history updated successfully"}
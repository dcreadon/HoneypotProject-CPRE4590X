import boto3
from datetime import datetime
import time

def lambda_handler(event, context):
    client = boto3.client('logs')
    
    # 1. Define your parameters
    # Make sure these match your actual AWS names exactly
    log_group = 'Honeypot-Activity-Logs'
    bucket_name = 'honeypot-logs-declan-christian-anish-justin' 
    
    # 2. Calculate time range (Yesterday to Now)
    to_time = int(round(time.time() * 1000))
    from_time = int(to_time - 86400000) # 24 hours in milliseconds
    
    # 3. Create a unique folder name based on the date
    date_prefix = datetime.now().strftime('%Y-%m-%d')
    
    # Dictionary used to bypass the Python 'from' keyword restriction
    export_args = {
        'taskName': f'export-{date_prefix}',
        'logGroupName': log_group,
        'from': from_time,
        'to': to_time,
        'destination': bucket_name,
        'destinationPrefix': f'archived-logs/{date_prefix}'
    }
    
    try:
        # The ** syntax unpacks the dictionary into the function call
        response = client.create_export_task(**export_args)
        print(f"Export task created: {response['taskId']}")
        return response['taskId']
    except Exception as e:
        print(f"Error: {str(e)}")
        raise e
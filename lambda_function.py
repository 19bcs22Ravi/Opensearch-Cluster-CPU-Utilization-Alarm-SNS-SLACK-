import boto3
import json
import logging
import os
import datetime
from urllib.request import Request, urlopen, URLError, HTTPError

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Define the Slack Webhook URL from environment variable
HOOK_URL = os.environ['SLACK_WEBHOOK_URL']

# Initialize AWS clients
cloudwatch = boto3.client('cloudwatch')
es = boto3.client('es')

def lambda_handler(event, context):
    try:
        # Log the entire event for debugging
        logger.info(f"Received event: {json.dumps(event)}")

        # Extract the alarm name and reason data from the event
        alarm_name, reason_data = extract_alarm_details(event)
        
        logger.info(f"Triggered alarm: {alarm_name}")

        if alarm_name == "systlab-opensearch-opensearch-cpu-utilization":
            domain_name = 'systlab-opensearch'
            cluster_id = get_opensearch_cluster_id(domain_name)
            
            logger.info(f"OpenSearch Domain ID: {cluster_id}")

            last_datapoint = reason_data['recentDatapoints'][-1]
            last_threshold = reason_data['threshold']

            notify_slack(f"WorkerNode for OpenSearch Cluster ID {cluster_id} has exceeded the CPU utilization threshold. "
                         f"Last datapoint: {last_datapoint}%, Threshold Exceeded: {last_threshold}%.")
        else:
            logger.info("Alarm name does not match the expected value.")
    
    except KeyError as e:
        logger.error(f"Key error: {e}")
    except Exception as e:
        logger.error(f"Error processing event: {e}")

def extract_alarm_details(event):
    if 'alarmData' in event and 'alarmName' in event['alarmData']:
        alarm_name = event['alarmData']['alarmName']
        reason_data = json.loads(event['alarmData']['state']['reasonData'])
        return alarm_name, reason_data
    else:
        logger.error("'alarmName' key not found in 'alarmData'. Event structure: " + json.dumps(event))
        raise KeyError("'alarmName' key not found in 'alarmData'")

def get_opensearch_cluster_id(domain_name):
    response = es.describe_elasticsearch_domain(DomainName=domain_name)
    return response['DomainStatus']['DomainId']

def notify_slack(message):
    slack_message = {
        'text': message
    }

    req = Request(HOOK_URL, json.dumps(slack_message).encode('utf-8'))
    
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted to Slack channel")
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)

"""
AWS Lambda Function: IAM Auto-Remediation
Automatically remediates IAM compliance violations.

Remediates:
- CIS 1.12: Disable unused credentials
- CIS 1.14: Alert on old access keys
"""

import json
import boto3
import logging
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = boto3.client('iam')
sns = boto3.client('sns')

SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:compliance-alerts'
MAX_CREDENTIAL_AGE_DAYS = 90
MAX_INACTIVE_DAYS = 45
DRY_RUN = False


def lambda_handler(event, context):
    """Main handler for IAM remediation."""
    logger.info(f"Starting IAM compliance scan")
    
    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "users_processed": 0,
        "keys_disabled": [],
        "alerts": []
    }
    
    try:
        # Get all IAM users
        paginator = iam.get_paginator('list_users')
        
        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']
                results['users_processed'] += 1
                
                # Check access keys
                check_access_keys(username, results)
        
        if results['keys_disabled'] or results['alerts']:
            send_notification(results)
        
        return {"statusCode": 200, "body": json.dumps(results)}
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        raise


def check_access_keys(username, results):
    """Check access keys for compliance."""
    try:
        keys = iam.list_access_keys(UserName=username)
        
        for key in keys['AccessKeyMetadata']:
            key_id = key['AccessKeyId']
            created = key['CreateDate']
            status = key['Status']
            
            if status != 'Active':
                continue
            
            # Calculate key age
            age_days = (datetime.now(timezone.utc) - created).days
            
            # Check last used
            try:
                last_used_info = iam.get_access_key_last_used(AccessKeyId=key_id)
                last_used = last_used_info['AccessKeyLastUsed'].get('LastUsedDate')
                
                if last_used:
                    inactive_days = (datetime.now(timezone.utc) - last_used).days
                else:
                    inactive_days = age_days
                    
            except Exception:
                inactive_days = age_days
            
            # CIS 1.12: Disable unused credentials
            if inactive_days > MAX_INACTIVE_DAYS:
                if not DRY_RUN:
                    iam.update_access_key(
                        UserName=username,
                        AccessKeyId=key_id,
                        Status='Inactive'
                    )
                    
                results['keys_disabled'].append({
                    'user': username,
                    'key_id': key_id,
                    'inactive_days': inactive_days,
                    'reason': 'CIS-1.12: Unused for >45 days'
                })
                logger.info(f"Disabled key {key_id} for {username}")
            
            # CIS 1.14: Alert on old keys
            elif age_days > MAX_CREDENTIAL_AGE_DAYS:
                results['alerts'].append({
                    'user': username,
                    'key_id': key_id,
                    'age_days': age_days,
                    'message': 'CIS-1.14: Key needs rotation'
                })
                
    except Exception as e:
        logger.error(f"Error checking {username}: {str(e)}")


def send_notification(results):
    """Send compliance notification."""
    try:
        message = f"""
IAM Compliance Scan Results
============================
Time: {results['timestamp']}
Users Processed: {results['users_processed']}

Keys Disabled (CIS 1.12):
{json.dumps(results['keys_disabled'], indent=2)}

Rotation Alerts (CIS 1.14):
{json.dumps(results['alerts'], indent=2)}
        """
        
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject="[COMPLIANCE] IAM Credential Report"
        )
    except Exception as e:
        logger.error(f"Notification error: {str(e)}")

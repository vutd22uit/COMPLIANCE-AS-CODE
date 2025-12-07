"""
AWS Lambda Function: S3 Auto-Remediation
Automatically remediates S3 bucket compliance violations.

This Lambda is triggered by:
- AWS Config rules
- CloudWatch Events
- EventBridge rules

Remediates:
- CIS 2.1.2: Enable encryption
- CIS 2.1.4: Block public access
- CIS 2.1.3: Enable versioning
"""

import json
import boto3
import logging
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
s3 = boto3.client('s3')
sns = boto3.client('sns')

# Configuration
SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:compliance-alerts'
DRY_RUN = False  # Set to True to test without making changes


def lambda_handler(event, context):
    """
    Main Lambda handler.
    Processes S3 compliance events and auto-remediates.
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        # Extract bucket name from event
        bucket_name = extract_bucket_name(event)
        
        if not bucket_name:
            logger.error("Could not extract bucket name from event")
            return {"statusCode": 400, "body": "Missing bucket name"}
        
        logger.info(f"Processing bucket: {bucket_name}")
        
        # Run remediation checks
        results = {
            "bucket": bucket_name,
            "timestamp": datetime.utcnow().isoformat(),
            "remediations": []
        }
        
        # CIS 2.1.4: Block public access
        if remediate_public_access(bucket_name):
            results["remediations"].append("public_access_blocked")
        
        # CIS 2.1.2: Enable encryption
        if remediate_encryption(bucket_name):
            results["remediations"].append("encryption_enabled")
        
        # CIS 2.1.3: Enable versioning
        if remediate_versioning(bucket_name):
            results["remediations"].append("versioning_enabled")
        
        # Send notification if any remediations were made
        if results["remediations"]:
            send_notification(results)
        
        return {
            "statusCode": 200,
            "body": json.dumps(results)
        }
        
    except Exception as e:
        logger.error(f"Error processing event: {str(e)}")
        raise


def extract_bucket_name(event):
    """Extract S3 bucket name from various event sources."""
    
    # AWS Config event
    if 'configRuleArn' in event:
        invoking_event = json.loads(event.get('invokingEvent', '{}'))
        return invoking_event.get('configurationItem', {}).get('resourceId')
    
    # S3 event
    if 'Records' in event:
        return event['Records'][0]['s3']['bucket']['name']
    
    # EventBridge/CloudWatch event
    if 'detail' in event:
        detail = event['detail']
        if 'requestParameters' in detail:
            return detail['requestParameters'].get('bucketName')
        if 'resourceId' in detail:
            return detail['resourceId']
    
    # Direct invocation
    if 'bucket_name' in event:
        return event['bucket_name']
    
    return None


def remediate_public_access(bucket_name):
    """
    CIS 2.1.4: Enable public access block on S3 bucket.
    """
    try:
        # Check current configuration
        try:
            current = s3.get_public_access_block(Bucket=bucket_name)
            config = current['PublicAccessBlockConfiguration']
            
            if all([
                config.get('BlockPublicAcls', False),
                config.get('IgnorePublicAcls', False),
                config.get('BlockPublicPolicy', False),
                config.get('RestrictPublicBuckets', False)
            ]):
                logger.info(f"Bucket {bucket_name} already has public access blocked")
                return False
                
        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            pass  # No config exists, need to create
        
        if DRY_RUN:
            logger.info(f"DRY RUN: Would block public access for {bucket_name}")
            return True
        
        # Apply public access block
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        logger.info(f"Successfully blocked public access for {bucket_name}")
        return True
        
    except Exception as e:
        logger.error(f"Error blocking public access for {bucket_name}: {str(e)}")
        return False


def remediate_encryption(bucket_name):
    """
    CIS 2.1.2: Enable server-side encryption on S3 bucket.
    """
    try:
        # Check current encryption
        try:
            current = s3.get_bucket_encryption(Bucket=bucket_name)
            logger.info(f"Bucket {bucket_name} already has encryption enabled")
            return False
        except s3.exceptions.ClientError as e:
            if e.response['Error']['Code'] != 'ServerSideEncryptionConfigurationNotFoundError':
                raise
        
        if DRY_RUN:
            logger.info(f"DRY RUN: Would enable encryption for {bucket_name}")
            return True
        
        # Enable AES256 encryption
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    },
                    'BucketKeyEnabled': True
                }]
            }
        )
        
        logger.info(f"Successfully enabled encryption for {bucket_name}")
        return True
        
    except Exception as e:
        logger.error(f"Error enabling encryption for {bucket_name}: {str(e)}")
        return False


def remediate_versioning(bucket_name):
    """
    CIS 2.1.3: Enable versioning on S3 bucket.
    """
    try:
        # Check current versioning status
        current = s3.get_bucket_versioning(Bucket=bucket_name)
        
        if current.get('Status') == 'Enabled':
            logger.info(f"Bucket {bucket_name} already has versioning enabled")
            return False
        
        if DRY_RUN:
            logger.info(f"DRY RUN: Would enable versioning for {bucket_name}")
            return True
        
        # Enable versioning
        s3.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        
        logger.info(f"Successfully enabled versioning for {bucket_name}")
        return True
        
    except Exception as e:
        logger.error(f"Error enabling versioning for {bucket_name}: {str(e)}")
        return False


def send_notification(results):
    """Send SNS notification about remediations."""
    try:
        message = {
            "default": json.dumps(results),
            "email": f"""
S3 Bucket Auto-Remediation Report
==================================
Bucket: {results['bucket']}
Time: {results['timestamp']}

Remediations Applied:
{chr(10).join('- ' + r for r in results['remediations'])}

This is an automated message from the Compliance-as-Code framework.
            """
        }
        
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=json.dumps(message),
            MessageStructure='json',
            Subject=f"[COMPLIANCE] S3 Auto-Remediation: {results['bucket']}"
        )
        
        logger.info(f"Notification sent for {results['bucket']}")
        
    except Exception as e:
        logger.error(f"Error sending notification: {str(e)}")

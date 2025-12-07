"""
AWS Lambda Function: Security Group Auto-Remediation
Automatically remediates Security Group compliance violations.

Triggered by AWS Config or CloudWatch Events when:
- Security group allows 0.0.0.0/0 to admin ports
- Security group allows all traffic from any source

Remediates:
- CIS 5.2: Remove open admin port access
"""

import json
import boto3
import logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client('ec2')
sns = boto3.client('sns')

# Configuration
SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:compliance-alerts'
ADMIN_PORTS = [22, 3389]  # SSH, RDP
DATABASE_PORTS = [3306, 5432, 1433, 1521, 27017, 6379]
DRY_RUN = False


def lambda_handler(event, context):
    """Main Lambda handler for security group remediation."""
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        sg_id = extract_security_group_id(event)
        
        if not sg_id:
            logger.error("Could not extract security group ID")
            return {"statusCode": 400, "body": "Missing security group ID"}
        
        results = {
            "security_group": sg_id,
            "timestamp": datetime.utcnow().isoformat(),
            "rules_revoked": []
        }
        
        # Get security group details
        response = ec2.describe_security_groups(GroupIds=[sg_id])
        
        if not response['SecurityGroups']:
            logger.error(f"Security group {sg_id} not found")
            return {"statusCode": 404, "body": "Security group not found"}
        
        sg = response['SecurityGroups'][0]
        
        # Find and remove dangerous rules
        for permission in sg.get('IpPermissions', []):
            dangerous_ranges = []
            
            for ip_range in permission.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    if is_dangerous_rule(permission):
                        dangerous_ranges.append(ip_range)
            
            if dangerous_ranges and not DRY_RUN:
                revoke_permission = {
                    'IpProtocol': permission['IpProtocol'],
                    'FromPort': permission.get('FromPort'),
                    'ToPort': permission.get('ToPort'),
                    'IpRanges': dangerous_ranges
                }
                
                ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[revoke_permission]
                )
                
                results['rules_revoked'].append({
                    'protocol': permission['IpProtocol'],
                    'from_port': permission.get('FromPort'),
                    'to_port': permission.get('ToPort'),
                    'cidr': '0.0.0.0/0'
                })
                
                logger.info(f"Revoked dangerous rule from {sg_id}")
        
        if results['rules_revoked']:
            send_notification(results)
        
        return {"statusCode": 200, "body": json.dumps(results)}
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        raise


def extract_security_group_id(event):
    """Extract security group ID from event."""
    if 'configRuleArn' in event:
        return event.get('resourceId')
    
    if 'detail' in event:
        params = event['detail'].get('requestParameters', {})
        return params.get('groupId')
    
    if 'security_group_id' in event:
        return event['security_group_id']
    
    return None


def is_dangerous_rule(permission):
    """Check if a permission is dangerous (admin/database ports)."""
    from_port = permission.get('FromPort', 0)
    to_port = permission.get('ToPort', 65535)
    
    # Check for all traffic
    if permission.get('IpProtocol') == '-1':
        return True
    
    # Check for admin ports
    for port in ADMIN_PORTS + DATABASE_PORTS:
        if from_port <= port <= to_port:
            return True
    
    return False


def send_notification(results):
    """Send SNS notification."""
    try:
        message = f"""
Security Group Auto-Remediation
================================
Security Group: {results['security_group']}
Time: {results['timestamp']}

Rules Revoked:
{json.dumps(results['rules_revoked'], indent=2)}
        """
        
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject=f"[CRITICAL] SG Remediation: {results['security_group']}"
        )
    except Exception as e:
        logger.error(f"Notification error: {str(e)}")

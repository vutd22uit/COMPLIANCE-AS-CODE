# CIS AWS Foundations Benchmark - Section 4: Monitoring
# InSpec Controls

# CIS 4.1: Ensure a log metric filter and alarm exist for unauthorized API calls
control 'cis-aws-4-1' do
  impact 0.7
  title 'Ensure a log metric filter and alarm exist for unauthorized API calls'
  desc 'Monitor unauthorized API calls to detect potential security issues.'

  tag cis: 'CIS-AWS-4.1'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'
  tag section: '4. Monitoring'

  # Pattern for unauthorized API calls
  filter_pattern = '{ ($.errorCode = "*UnauthorizedAccess*") || ($.errorCode = "AccessDenied*") }'

  describe 'CloudWatch Log Metric Filter for unauthorized API calls' do
    subject { aws_cloudwatch_log_metric_filter(filter_name: 'unauthorized-api-calls') }
    it { should exist }
    its('filter_pattern') { should include 'UnauthorizedAccess' }
  end

  describe 'CloudWatch Alarm for unauthorized API calls' do
    subject { aws_cloudwatch_alarm(alarm_name: 'unauthorized-api-calls-alarm') }
    it { should exist }
  end
end

# CIS 4.2: Ensure a log metric filter and alarm exist for Console sign-in without MFA
control 'cis-aws-4-2' do
  impact 0.7
  title 'Ensure a log metric filter and alarm exist for Console sign-in without MFA'
  desc 'Monitor console sign-ins without MFA to detect insecure access.'

  tag cis: 'CIS-AWS-4.2'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  # Pattern for console login without MFA
  filter_pattern = '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }'

  describe 'CloudWatch Log Metric Filter for console login without MFA' do
    subject { aws_cloudwatch_log_metric_filter(filter_name: 'console-login-no-mfa') }
    it { should exist }
    its('filter_pattern') { should include 'ConsoleLogin' }
    its('filter_pattern') { should include 'MFAUsed' }
  end

  describe 'CloudWatch Alarm for console login without MFA' do
    subject { aws_cloudwatch_alarm(alarm_name: 'console-login-no-mfa-alarm') }
    it { should exist }
  end
end

# CIS 4.3: Ensure a log metric filter and alarm exist for 'root' account usage
control 'cis-aws-4-3' do
  impact 1.0
  title "Ensure a log metric filter and alarm exist for usage of 'root' account"
  desc 'Monitor root account usage to detect unauthorized administrative access.'

  tag cis: 'CIS-AWS-4.3'
  tag severity: 'critical'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  # Pattern for root account usage
  filter_pattern = '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'

  describe 'CloudWatch Log Metric Filter for root account usage' do
    subject { aws_cloudwatch_log_metric_filter(filter_name: 'root-account-usage') }
    it { should exist }
    its('filter_pattern') { should include 'Root' }
  end

  describe 'CloudWatch Alarm for root account usage' do
    subject { aws_cloudwatch_alarm(alarm_name: 'root-account-usage-alarm') }
    it { should exist }
    its('actions_enabled') { should be true }
  end
end

# CIS 4.4: Ensure a log metric filter and alarm exist for IAM policy changes
control 'cis-aws-4-4' do
  impact 0.7
  title 'Ensure a log metric filter and alarm exist for IAM policy changes'
  desc 'Monitor IAM policy changes to detect unauthorized permission modifications.'

  tag cis: 'CIS-AWS-4.4'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  iam_events = [
    'DeleteGroupPolicy', 'DeleteRolePolicy', 'DeleteUserPolicy',
    'PutGroupPolicy', 'PutRolePolicy', 'PutUserPolicy',
    'CreatePolicy', 'DeletePolicy', 'CreatePolicyVersion', 'DeletePolicyVersion',
    'AttachRolePolicy', 'DetachRolePolicy', 'AttachUserPolicy', 'DetachUserPolicy',
    'AttachGroupPolicy', 'DetachGroupPolicy'
  ]

  describe 'CloudWatch Log Metric Filter for IAM policy changes' do
    subject { aws_cloudwatch_log_metric_filter(filter_name: 'iam-policy-changes') }
    it { should exist }
    # Pattern should include IAM policy change events
    its('filter_pattern') { should include 'PolicyVersion' }
  end

  describe 'CloudWatch Alarm for IAM policy changes' do
    subject { aws_cloudwatch_alarm(alarm_name: 'iam-policy-changes-alarm') }
    it { should exist }
  end
end

# CIS 4.5: Ensure a log metric filter and alarm exist for CloudTrail configuration changes
control 'cis-aws-4-5' do
  impact 0.7
  title 'Ensure a log metric filter and alarm exist for CloudTrail configuration changes'
  desc 'Monitor CloudTrail configuration changes to detect attempts to disable logging.'

  tag cis: 'CIS-AWS-4.5'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  cloudtrail_events = [
    'CreateTrail', 'UpdateTrail', 'DeleteTrail',
    'StartLogging', 'StopLogging'
  ]

  describe 'CloudWatch Log Metric Filter for CloudTrail changes' do
    subject { aws_cloudwatch_log_metric_filter(filter_name: 'cloudtrail-config-changes') }
    it { should exist }
    its('filter_pattern') { should include 'Trail' }
  end

  describe 'CloudWatch Alarm for CloudTrail changes' do
    subject { aws_cloudwatch_alarm(alarm_name: 'cloudtrail-config-changes-alarm') }
    it { should exist }
  end
end

# CIS 4.6: Ensure a log metric filter and alarm exist for Console authentication failures
control 'cis-aws-4-6' do
  impact 0.5
  title 'Ensure a log metric filter and alarm exist for Console authentication failures'
  desc 'Monitor console authentication failures to detect brute force attacks.'

  tag cis: 'CIS-AWS-4.6'
  tag severity: 'medium'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  describe 'CloudWatch Log Metric Filter for console auth failures' do
    subject { aws_cloudwatch_log_metric_filter(filter_name: 'console-auth-failure') }
    it { should exist }
    its('filter_pattern') { should include 'ConsoleLogin' }
    its('filter_pattern') { should include 'Failure' }
  end

  describe 'CloudWatch Alarm for console auth failures' do
    subject { aws_cloudwatch_alarm(alarm_name: 'console-auth-failure-alarm') }
    it { should exist }
  end
end

# CIS 4.7: Ensure a log metric filter and alarm exist for CMK key deletion
control 'cis-aws-4-7' do
  impact 1.0
  title 'Ensure a log metric filter and alarm exist for disabling or scheduled deletion of CMKs'
  desc 'Monitor KMS key deletion/disable actions to detect attempts to compromise encryption.'

  tag cis: 'CIS-AWS-4.7'
  tag severity: 'critical'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  describe 'CloudWatch Log Metric Filter for CMK changes' do
    subject { aws_cloudwatch_log_metric_filter(filter_name: 'cmk-disable-delete') }
    it { should exist }
    its('filter_pattern') { should include 'DisableKey' }
  end

  describe 'CloudWatch Alarm for CMK changes' do
    subject { aws_cloudwatch_alarm(alarm_name: 'cmk-disable-delete-alarm') }
    it { should exist }
  end
end

# CIS 4.8: Ensure a log metric filter and alarm exist for S3 bucket policy changes
control 'cis-aws-4-8' do
  impact 0.7
  title 'Ensure a log metric filter and alarm exist for S3 bucket policy changes'
  desc 'Monitor S3 bucket policy changes to detect unauthorized access modifications.'

  tag cis: 'CIS-AWS-4.8'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  s3_events = [
    'PutBucketAcl', 'PutBucketPolicy', 'PutBucketCors',
    'PutBucketLifecycle', 'PutBucketReplication', 'DeleteBucketPolicy',
    'DeleteBucketCors', 'DeleteBucketLifecycle', 'DeleteBucketReplication'
  ]

  describe 'CloudWatch Log Metric Filter for S3 policy changes' do
    subject { aws_cloudwatch_log_metric_filter(filter_name: 's3-bucket-policy-changes') }
    it { should exist }
    its('filter_pattern') { should include 'Bucket' }
  end

  describe 'CloudWatch Alarm for S3 policy changes' do
    subject { aws_cloudwatch_alarm(alarm_name: 's3-bucket-policy-changes-alarm') }
    it { should exist }
  end
end

# CIS 4.9: Ensure a log metric filter and alarm exist for AWS Config configuration changes
control 'cis-aws-4-9' do
  impact 0.7
  title 'Ensure a log metric filter and alarm exist for AWS Config configuration changes'
  desc 'Monitor AWS Config changes to detect attempts to disable configuration recording.'

  tag cis: 'CIS-AWS-4.9'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  config_events = [
    'StopConfigurationRecorder', 'DeleteDeliveryChannel',
    'PutDeliveryChannel', 'PutConfigurationRecorder'
  ]

  describe 'CloudWatch Log Metric Filter for AWS Config changes' do
    subject { aws_cloudwatch_log_metric_filter(filter_name: 'aws-config-changes') }
    it { should exist }
    its('filter_pattern') { should include 'ConfigurationRecorder' }
  end

  describe 'CloudWatch Alarm for AWS Config changes' do
    subject { aws_cloudwatch_alarm(alarm_name: 'aws-config-changes-alarm') }
    it { should exist }
  end
end

# CIS 4.10: Ensure a log metric filter and alarm exist for security group changes
control 'cis-aws-4-10' do
  impact 0.7
  title 'Ensure a log metric filter and alarm exist for security group changes'
  desc 'Monitor security group changes to detect unauthorized network access modifications.'

  tag cis: 'CIS-AWS-4.10'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  sg_events = [
    'AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress',
    'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress',
    'CreateSecurityGroup', 'DeleteSecurityGroup'
  ]

  describe 'CloudWatch Log Metric Filter for security group changes' do
    subject { aws_cloudwatch_log_metric_filter(filter_name: 'security-group-changes') }
    it { should exist }
    its('filter_pattern') { should include 'SecurityGroup' }
  end

  describe 'CloudWatch Alarm for security group changes' do
    subject { aws_cloudwatch_alarm(alarm_name: 'security-group-changes-alarm') }
    it { should exist }
  end
end

# CIS 4.11: Ensure a log metric filter and alarm exist for NACL changes
control 'cis-aws-4-11' do
  impact 0.7
  title 'Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)'
  desc 'Monitor NACL changes to detect unauthorized network access modifications.'

  tag cis: 'CIS-AWS-4.11'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  nacl_events = [
    'CreateNetworkAcl', 'CreateNetworkAclEntry',
    'DeleteNetworkAcl', 'DeleteNetworkAclEntry',
    'ReplaceNetworkAclAssociation', 'ReplaceNetworkAclEntry'
  ]

  describe 'CloudWatch Log Metric Filter for NACL changes' do
    subject { aws_cloudwatch_log_metric_filter(filter_name: 'nacl-changes') }
    it { should exist }
    its('filter_pattern') { should include 'NetworkAcl' }
  end

  describe 'CloudWatch Alarm for NACL changes' do
    subject { aws_cloudwatch_alarm(alarm_name: 'nacl-changes-alarm') }
    it { should exist }
  end
end

# CIS 4.12: Ensure a log metric filter and alarm exist for network gateway changes
control 'cis-aws-4-12' do
  impact 0.7
  title 'Ensure a log metric filter and alarm exist for changes to network gateways'
  desc 'Monitor gateway changes to detect unauthorized network access modifications.'

  tag cis: 'CIS-AWS-4.12'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  gw_events = [
    'CreateCustomerGateway', 'DeleteCustomerGateway',
    'AttachInternetGateway', 'CreateInternetGateway',
    'DeleteInternetGateway', 'DetachInternetGateway'
  ]

  describe 'CloudWatch Log Metric Filter for network gateway changes' do
    subject { aws_cloudwatch_log_metric_filter(filter_name: 'network-gateway-changes') }
    it { should exist }
    its('filter_pattern') { should include 'Gateway' }
  end

  describe 'CloudWatch Alarm for network gateway changes' do
    subject { aws_cloudwatch_alarm(alarm_name: 'network-gateway-changes-alarm') }
    it { should exist }
  end
end

# CIS 4.13: Ensure a log metric filter and alarm exist for route table changes
control 'cis-aws-4-13' do
  impact 0.7
  title 'Ensure a log metric filter and alarm exist for route table changes'
  desc 'Monitor route table changes to detect unauthorized network routing modifications.'

  tag cis: 'CIS-AWS-4.13'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  rt_events = [
    'CreateRoute', 'CreateRouteTable', 'ReplaceRoute',
    'ReplaceRouteTableAssociation', 'DeleteRouteTable',
    'DeleteRoute', 'DisassociateRouteTable'
  ]

  describe 'CloudWatch Log Metric Filter for route table changes' do
    subject { aws_cloudwatch_log_metric_filter(filter_name: 'route-table-changes') }
    it { should exist }
    its('filter_pattern') { should include 'Route' }
  end

  describe 'CloudWatch Alarm for route table changes' do
    subject { aws_cloudwatch_alarm(alarm_name: 'route-table-changes-alarm') }
    it { should exist }
  end
end

# CIS 4.14: Ensure a log metric filter and alarm exist for VPC changes
control 'cis-aws-4-14' do
  impact 0.7
  title 'Ensure a log metric filter and alarm exist for VPC changes'
  desc 'Monitor VPC changes to detect unauthorized network modifications.'

  tag cis: 'CIS-AWS-4.14'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  vpc_events = [
    'CreateVpc', 'DeleteVpc', 'ModifyVpcAttribute',
    'AcceptVpcPeeringConnection', 'CreateVpcPeeringConnection',
    'DeleteVpcPeeringConnection', 'RejectVpcPeeringConnection',
    'AttachClassicLinkVpc', 'DetachClassicLinkVpc',
    'DisableVpcClassicLink', 'EnableVpcClassicLink'
  ]

  describe 'CloudWatch Log Metric Filter for VPC changes' do
    subject { aws_cloudwatch_log_metric_filter(filter_name: 'vpc-changes') }
    it { should exist }
    its('filter_pattern') { should include 'Vpc' }
  end

  describe 'CloudWatch Alarm for VPC changes' do
    subject { aws_cloudwatch_alarm(alarm_name: 'vpc-changes-alarm') }
    it { should exist }
  end
end

# CIS 4.15: Ensure a log metric filter and alarm exist for AWS Organizations changes
control 'cis-aws-4-15' do
  impact 1.0
  title 'Ensure a log metric filter and alarm exist for AWS Organizations changes'
  desc 'Monitor AWS Organizations changes to detect unauthorized organizational modifications.'

  tag cis: 'CIS-AWS-4.15'
  tag severity: 'critical'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'
  
  only_if('AWS Organizations is used') do
    # Check if AWS Organizations is configured
    true  # Placeholder - should be dynamic check
  end

  describe 'CloudWatch Log Metric Filter for Organizations changes' do
    subject { aws_cloudwatch_log_metric_filter(filter_name: 'organizations-changes') }
    it { should exist }
    its('filter_pattern') { should include 'organizations.amazonaws.com' }
  end

  describe 'CloudWatch Alarm for Organizations changes' do
    subject { aws_cloudwatch_alarm(alarm_name: 'organizations-changes-alarm') }
    it { should exist }
  end
end

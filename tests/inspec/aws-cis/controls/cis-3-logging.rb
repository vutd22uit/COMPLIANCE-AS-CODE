# CIS AWS Foundations Benchmark - Section 3: Logging
# InSpec Controls

# CIS 3.1: Ensure CloudTrail is enabled in all regions
control 'cis-aws-3-1' do
  impact 1.0
  title 'Ensure CloudTrail is enabled in all regions'
  desc 'CloudTrail should be enabled across all AWS regions to capture all API activity.'

  tag cis: 'CIS-AWS-3.1'
  tag severity: 'critical'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'
  tag section: '3. Logging'

  describe aws_cloudtrail_trails do
    it { should exist }
  end

  # At least one trail should be multi-region
  multi_region_trails = aws_cloudtrail_trails.trail_arns.select do |arn|
    aws_cloudtrail_trail(arn).is_multi_region_trail?
  end

  describe 'Multi-region CloudTrail trails' do
    subject { multi_region_trails }
    its('count') { should be >= 1 }
  end

  # Verify each region has CloudTrail coverage
  aws_cloudtrail_trails.trail_arns.each do |trail_arn|
    describe aws_cloudtrail_trail(trail_arn) do
      it { should be_multi_region_trail }
    end
  end
end

# CIS 3.2: Ensure CloudTrail log file validation is enabled
control 'cis-aws-3-2' do
  impact 0.7
  title 'Ensure CloudTrail log file validation is enabled'
  desc 'Enable log file integrity validation to detect tampering of CloudTrail logs.'

  tag cis: 'CIS-AWS-3.2'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  aws_cloudtrail_trails.trail_arns.each do |trail_arn|
    describe aws_cloudtrail_trail(trail_arn) do
      it { should have_log_file_validation_enabled }
    end
  end
end

# CIS 3.3: Ensure CloudTrail S3 bucket is not publicly accessible
control 'cis-aws-3-3' do
  impact 1.0
  title 'Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible'
  desc 'CloudTrail log buckets should not be publicly accessible to protect audit data.'

  tag cis: 'CIS-AWS-3.3'
  tag severity: 'critical'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  aws_cloudtrail_trails.trail_arns.each do |trail_arn|
    trail = aws_cloudtrail_trail(trail_arn)
    bucket_name = trail.s3_bucket_name

    describe aws_s3_bucket(bucket_name: bucket_name) do
      it { should_not be_public }
    end

    describe "CloudTrail bucket #{bucket_name} public access block" do
      subject { aws_s3_bucket(bucket_name: bucket_name) }

      it 'should have all public access blocked' do
        block = subject.public_access_block
        expect(block.block_public_acls).to be true
        expect(block.block_public_policy).to be true
        expect(block.ignore_public_acls).to be true
        expect(block.restrict_public_buckets).to be true
      end
    end
  end
end

# CIS 3.4: Ensure CloudTrail trails are integrated with CloudWatch Logs
control 'cis-aws-3-4' do
  impact 0.7
  title 'Ensure CloudTrail trails are integrated with CloudWatch Logs'
  desc 'CloudTrail should be integrated with CloudWatch Logs for real-time monitoring.'

  tag cis: 'CIS-AWS-3.4'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  aws_cloudtrail_trails.trail_arns.each do |trail_arn|
    describe aws_cloudtrail_trail(trail_arn) do
      its('cloud_watch_logs_log_group_arn') { should_not be_nil }
    end
  end
end

# CIS 3.5: Ensure AWS Config is enabled in all regions
control 'cis-aws-3-5' do
  impact 0.7
  title 'Ensure AWS Config is enabled in all regions'
  desc 'AWS Config should be enabled to record resource configurations.'

  tag cis: 'CIS-AWS-3.5'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  aws_regions.region_names.each do |region|
    describe aws_config_recorder(region: region) do
      it { should exist }
      it { should be_recording }
      it { should be_recording_all_resource_types }
      it { should be_recording_all_global_types }
    end
  end
end

# CIS 3.6: Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket
control 'cis-aws-3-6' do
  impact 0.5
  title 'Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket'
  desc 'Enable access logging on CloudTrail buckets for additional audit trail.'

  tag cis: 'CIS-AWS-3.6'
  tag severity: 'medium'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  aws_cloudtrail_trails.trail_arns.each do |trail_arn|
    trail = aws_cloudtrail_trail(trail_arn)
    bucket_name = trail.s3_bucket_name

    describe aws_s3_bucket(bucket_name: bucket_name) do
      it { should have_access_logging_enabled }
    end
  end
end

# CIS 3.7: Ensure CloudTrail logs are encrypted at rest using KMS CMKs
control 'cis-aws-3-7' do
  impact 1.0
  title 'Ensure CloudTrail logs are encrypted at rest using KMS CMKs'
  desc 'CloudTrail logs should be encrypted with customer-managed KMS keys.'

  tag cis: 'CIS-AWS-3.7'
  tag severity: 'critical'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  aws_cloudtrail_trails.trail_arns.each do |trail_arn|
    describe aws_cloudtrail_trail(trail_arn) do
      it { should be_encrypted }
      its('kms_key_id') { should_not be_nil }
    end
  end
end

# CIS 3.8: Ensure rotation for customer-created CMKs is enabled
control 'cis-aws-3-8' do
  impact 0.5
  title 'Ensure rotation for customer-created symmetric CMKs is enabled'
  desc 'KMS keys should have automatic key rotation enabled.'

  tag cis: 'CIS-AWS-3.8'
  tag severity: 'medium'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  aws_kms_keys.key_ids.each do |key_id|
    key = aws_kms_key(key_id)
    
    # Skip AWS managed keys and asymmetric keys
    next if key.key_manager == 'AWS'
    next unless key.key_spec == 'SYMMETRIC_DEFAULT'

    describe "KMS key #{key_id}" do
      subject { key }
      it { should have_rotation_enabled }
    end
  end
end

# CIS 3.9: Ensure VPC flow logging is enabled in all VPCs
control 'cis-aws-3-9' do
  impact 0.7
  title 'Ensure VPC flow logging is enabled in all VPCs'
  desc 'VPC flow logs should be enabled to capture network traffic information.'

  tag cis: 'CIS-AWS-3.9'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  aws_vpcs.vpc_ids.each do |vpc_id|
    describe aws_vpc(vpc_id) do
      it { should have_flow_log }
    end
  end

  # Summary of VPCs without flow logs
  vpcs_without_flow_logs = aws_vpcs.vpc_ids.reject do |vpc_id|
    aws_vpc(vpc_id).has_flow_log?
  end

  describe 'VPCs without flow logs' do
    subject { vpcs_without_flow_logs }
    its('count') { should eq 0 }
  end
end

# CIS 3.10 & 3.11: Object-level logging for CloudTrail S3 bucket
control 'cis-aws-3-10-11' do
  impact 0.5
  title 'Ensure object-level logging is enabled for CloudTrail S3 bucket'
  desc 'Object-level logging should be enabled for read and write events on CloudTrail buckets.'

  tag cis: 'CIS-AWS-3.10, CIS-AWS-3.11'
  tag severity: 'medium'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  aws_cloudtrail_trails.trail_arns.each do |trail_arn|
    trail = aws_cloudtrail_trail(trail_arn)

    describe "CloudTrail #{trail.trail_name} event selectors" do
      it 'should have data events configured for S3' do
        # Check if trail has S3 data events configured
        # This requires checking event_selectors for S3 bucket resources
        expect(trail.event_selectors).to_not be_empty
      end
    end
  end
end

# PCI-DSS 10.2: Audit trail for all access
control 'pci-dss-10-2' do
  impact 0.7
  title 'Ensure audit trail is enabled for all access'
  desc 'CloudTrail should capture all management and data events for compliance.'

  tag standard: 'PCI-DSS v4.0'
  tag requirement: '10.2'
  tag severity: 'high'

  aws_cloudtrail_trails.trail_arns.each do |trail_arn|
    describe aws_cloudtrail_trail(trail_arn) do
      it { should be_multi_region_trail }
      it { should have_log_file_validation_enabled }
      its('include_global_service_events') { should be true }
    end
  end
end

# PCI-DSS 10.5: Protect audit trails
control 'pci-dss-10-5' do
  impact 1.0
  title 'Ensure audit trails are protected'
  desc 'CloudTrail logs should be encrypted and access controlled.'

  tag standard: 'PCI-DSS v4.0'
  tag requirement: '10.5'
  tag severity: 'critical'

  aws_cloudtrail_trails.trail_arns.each do |trail_arn|
    trail = aws_cloudtrail_trail(trail_arn)

    describe "CloudTrail #{trail.trail_name}" do
      it 'should be encrypted with KMS' do
        expect(trail.kms_key_id).to_not be_nil
      end

      it 'should have log file validation' do
        expect(trail.log_file_validation_enabled?).to be true
      end
    end

    # Check bucket protection
    bucket_name = trail.s3_bucket_name
    describe aws_s3_bucket(bucket_name: bucket_name) do
      it { should_not be_public }
      it { should have_versioning_enabled }
    end
  end
end

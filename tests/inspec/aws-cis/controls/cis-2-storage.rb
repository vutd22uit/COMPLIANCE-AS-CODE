# CIS AWS Foundations Benchmark - Section 2: Storage
# InSpec Controls

# CIS 2.1.1: Ensure S3 Bucket Policy is set to deny HTTP requests
control 'cis-aws-2-1-1' do
  impact 1.0
  title 'Ensure S3 Bucket Policy denies HTTP requests'
  desc 'S3 bucket policies should require HTTPS for all requests to ensure data in transit is encrypted.'

  tag cis: 'CIS-AWS-2.1.1'
  tag severity: 'critical'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'
  tag section: '2. Storage'

  aws_s3_buckets.bucket_names.each do |bucket_name|
    describe "S3 bucket #{bucket_name}" do
      subject { aws_s3_bucket(bucket_name: bucket_name) }

      # Check bucket policy for SecureTransport condition
      it 'should have a bucket policy enforcing HTTPS' do
        policy = subject.bucket_policy
        if policy
          expect(policy.to_s).to include('aws:SecureTransport')
        else
          skip "Bucket #{bucket_name} has no policy - manual review required"
        end
      end
    end
  end
end

# CIS 2.1.2: Ensure S3 buckets are encrypted at rest
control 'cis-aws-2-1-2' do
  impact 1.0
  title 'Ensure S3 buckets have encryption enabled'
  desc 'S3 buckets should have server-side encryption enabled to protect data at rest.'

  tag cis: 'CIS-AWS-2.1.2'
  tag severity: 'critical'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  aws_s3_buckets.bucket_names.each do |bucket_name|
    describe aws_s3_bucket(bucket_name: bucket_name) do
      it { should have_default_encryption_enabled }
    end
  end

  # Count violations for reporting
  unencrypted_buckets = aws_s3_buckets.bucket_names.select do |name|
    !aws_s3_bucket(bucket_name: name).has_default_encryption_enabled?
  end

  if unencrypted_buckets.any?
    describe 'Unencrypted S3 buckets' do
      subject { unencrypted_buckets }
      its('count') { should eq 0 }
    end
  end
end

# CIS 2.1.3: Ensure S3 bucket access logging is enabled
control 'cis-aws-2-1-3' do
  impact 0.7
  title 'Ensure S3 buckets have access logging enabled'
  desc 'S3 bucket access logging provides audit trails for bucket access.'

  tag cis: 'CIS-AWS-2.1.3'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  # Exclude logging buckets themselves to avoid infinite loops
  logging_bucket_patterns = ['log', 'audit', 'access-log']

  aws_s3_buckets.bucket_names.each do |bucket_name|
    # Skip if this is a logging bucket
    next if logging_bucket_patterns.any? { |pattern| bucket_name.downcase.include?(pattern) }

    describe aws_s3_bucket(bucket_name: bucket_name) do
      it { should have_access_logging_enabled }
    end
  end
end

# CIS 2.1.4: Ensure S3 Buckets have 'Block public access' enabled
control 'cis-aws-2-1-4' do
  impact 1.0
  title "Ensure S3 buckets have 'Block public access' enabled"
  desc 'S3 buckets should have all public access block settings enabled.'

  tag cis: 'CIS-AWS-2.1.4'
  tag severity: 'critical'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  aws_s3_buckets.bucket_names.each do |bucket_name|
    describe aws_s3_bucket(bucket_name: bucket_name) do
      it { should_not be_public }
    end

    # Check public access block configuration
    describe "S3 bucket #{bucket_name} public access block" do
      subject { aws_s3_bucket(bucket_name: bucket_name) }

      it 'should block public ACLs' do
        expect(subject.public_access_block.block_public_acls).to be true
      end

      it 'should block public policies' do
        expect(subject.public_access_block.block_public_policy).to be true
      end

      it 'should ignore public ACLs' do
        expect(subject.public_access_block.ignore_public_acls).to be true
      end

      it 'should restrict public buckets' do
        expect(subject.public_access_block.restrict_public_buckets).to be true
      end
    end
  end
end

# CIS 2.2.1: Ensure EBS volume encryption is enabled
control 'cis-aws-2-2-1' do
  impact 1.0
  title 'Ensure EBS volume encryption is enabled'
  desc 'EBS volumes should be encrypted to protect data at rest.'

  tag cis: 'CIS-AWS-2.2.1'
  tag severity: 'critical'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  # Check default EBS encryption setting
  describe aws_ebs_encryption_by_default do
    it { should be_enabled }
  end

  # Check individual volumes
  aws_ebs_volumes.volume_ids.each do |volume_id|
    describe aws_ebs_volume(volume_id: volume_id) do
      it { should be_encrypted }
    end
  end

  # Count unencrypted volumes
  unencrypted_volumes = aws_ebs_volumes.where(encrypted: false)
  
  describe 'Unencrypted EBS volumes' do
    subject { unencrypted_volumes.volume_ids }
    its('count') { should eq 0 }
  end
end

# CIS 2.3.1: Ensure RDS instances have encryption enabled
control 'cis-aws-2-3-1' do
  impact 1.0
  title 'Ensure encryption is enabled for RDS instances'
  desc 'RDS instances should have encryption enabled to protect data at rest.'

  tag cis: 'CIS-AWS-2.3.1'
  tag severity: 'critical'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  aws_rds_instances.db_instance_identifiers.each do |db_id|
    describe aws_rds_instance(db_id) do
      it { should have_encrypted_storage }
    end
  end
end

# CIS 2.3.2: Ensure RDS DB instances prohibit public access
control 'cis-aws-2-3-2' do
  impact 1.0
  title 'Ensure RDS DB instances prohibit public access'
  desc 'RDS instances should not be publicly accessible to reduce attack surface.'

  tag cis: 'CIS-AWS-2.3.2'
  tag severity: 'critical'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  aws_rds_instances.db_instance_identifiers.each do |db_id|
    describe aws_rds_instance(db_id) do
      it { should_not be_publicly_accessible }
    end
  end

  # Summary of public RDS instances
  public_dbs = aws_rds_instances.where(publicly_accessible: true)
  
  describe 'Publicly accessible RDS instances' do
    subject { public_dbs.db_instance_identifiers }
    its('count') { should eq 0 }
  end
end

# ISO 27017 CLD.10.1.1: KMS Encryption for sensitive data
control 'iso-27017-cld-10-1-1' do
  impact 0.7
  title 'Ensure S3 buckets with sensitive data use KMS encryption'
  desc 'S3 buckets containing sensitive data should use AWS KMS for encryption.'

  tag standard: 'ISO 27017:2015'
  tag control: 'CLD.10.1.1'
  tag severity: 'high'

  # Check buckets with sensitive data tags
  sensitive_classifications = ['Confidential', 'PCI', 'PHI', 'PII']

  aws_s3_buckets.bucket_names.each do |bucket_name|
    bucket = aws_s3_bucket(bucket_name: bucket_name)
    
    # Check if bucket has sensitive data classification
    data_classification = bucket.tags['DataClassification'] rescue nil
    
    next unless sensitive_classifications.include?(data_classification)

    describe "Sensitive S3 bucket #{bucket_name}" do
      it 'should use KMS encryption' do
        encryption = bucket.server_side_encryption_configuration
        expect(encryption).to_not be_nil
        expect(encryption[:sse_algorithm]).to eq('aws:kms')
      end
    end
  end
end

# PCI-DSS 3.4.1: Render cardholder data unreadable
control 'pci-dss-3-4-1' do
  impact 1.0
  title 'Ensure PCI data is encrypted with strong encryption'
  desc 'S3 buckets containing cardholder data must use KMS encryption.'

  tag standard: 'PCI-DSS v4.0'
  tag requirement: '3.4.1'
  tag severity: 'critical'

  aws_s3_buckets.bucket_names.each do |bucket_name|
    bucket = aws_s3_bucket(bucket_name: bucket_name)
    data_classification = bucket.tags['DataClassification'] rescue nil

    next unless data_classification == 'PCI'

    describe "PCI S3 bucket #{bucket_name}" do
      it 'must have KMS encryption' do
        encryption = bucket.server_side_encryption_configuration
        expect(encryption).to_not be_nil
        expect(encryption[:sse_algorithm]).to eq('aws:kms')
      end

      it 'must have versioning enabled' do
        expect(bucket.versioning).to eq('Enabled')
      end

      it 'must not be public' do
        expect(bucket).to_not be_public
      end
    end
  end
end

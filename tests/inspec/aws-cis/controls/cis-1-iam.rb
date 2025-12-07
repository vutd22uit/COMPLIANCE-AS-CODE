# CIS AWS Foundations Benchmark - Section 1: Identity and Access Management
# InSpec Controls

# CIS 1.4: Ensure no 'root' user account access key exists
control 'cis-aws-1-4' do
  impact 1.0
  title "Ensure no 'root' user account access key exists"
  desc "The root user is the most privileged user in an AWS account. Access keys provide programmatic access to AWS. No access keys should be created for the root account."

  tag cis: 'CIS-AWS-1.4'
  tag severity: 'critical'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'
  tag section: '1. Identity and Access Management'

  describe aws_iam_root_user do
    it { should_not have_access_key }
  end

  # Evidence for audit
  if aws_iam_root_user.has_access_key?
    describe "Root user access key detection" do
      subject { "VIOLATION: Root user has access keys" }
      it { should cmp "Root user should not have access keys" }
    end
  end
end

# CIS 1.5: Ensure MFA is enabled for the 'root' user account
control 'cis-aws-1-5' do
  impact 1.0
  title "Ensure MFA is enabled for the 'root' user account"
  desc "The root user is the most privileged user in an AWS account. MFA adds an extra layer of protection on top of a username and password."

  tag cis: 'CIS-AWS-1.5'
  tag severity: 'critical'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  describe aws_iam_root_user do
    it { should have_mfa_enabled }
  end
end

# CIS 1.8: Ensure IAM password policy requires minimum length of 14 or greater
control 'cis-aws-1-8' do
  impact 0.7
  title 'Ensure IAM password policy requires minimum length of 14 or greater'
  desc 'Password policies are used to enforce password complexity requirements. IAM password policies should require a minimum password length of 14.'

  tag cis: 'CIS-AWS-1.8'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  describe aws_iam_password_policy do
    it { should exist }
    its('minimum_password_length') { should be >= 14 }
  end
end

# CIS 1.9: Ensure IAM password policy prevents password reuse
control 'cis-aws-1-9' do
  impact 0.5
  title 'Ensure IAM password policy prevents password reuse'
  desc 'IAM password policies should prevent the reuse of passwords. Recommended to remember at least 24 passwords.'

  tag cis: 'CIS-AWS-1.9'
  tag severity: 'medium'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  describe aws_iam_password_policy do
    it { should exist }
    it { should prevent_password_reuse }
    its('number_of_passwords_to_remember') { should be >= 24 }
  end
end

# CIS 1.10: Ensure multi-factor authentication (MFA) is enabled for all IAM users
control 'cis-aws-1-10' do
  impact 0.7
  title 'Ensure MFA is enabled for all IAM users with console password'
  desc 'Multi-factor authentication (MFA) adds an extra layer of protection on top of a username and password.'

  tag cis: 'CIS-AWS-1.10'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  aws_iam_users.where { has_console_password }.usernames.each do |username|
    describe aws_iam_user(username) do
      it { should have_mfa_enabled }
    end
  end

  # Count violations
  users_without_mfa = aws_iam_users.where { has_console_password && !has_mfa_enabled }.usernames

  if users_without_mfa.any?
    describe "IAM users without MFA" do
      subject { users_without_mfa }
      its('count') { should eq 0 }
      it { should be_empty }
    end
  end
end

# CIS 1.12: Ensure credentials unused for 45 days or greater are disabled
control 'cis-aws-1-12' do
  impact 0.5
  title 'Ensure credentials unused for 45 days or greater are disabled'
  desc 'AWS IAM users can access AWS resources using different types of credentials. Disable unused credentials to reduce attack surface.'

  tag cis: 'CIS-AWS-1.12'
  tag severity: 'medium'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  max_inactive_days = 45

  # Check access keys
  aws_iam_users.usernames.each do |username|
    user = aws_iam_user(username)

    user.access_keys.each do |access_key|
      next unless access_key[:active]

      days_inactive = (Date.today - access_key[:last_used_date].to_date).to_i rescue nil

      if days_inactive && days_inactive > max_inactive_days
        describe "Access key #{access_key[:access_key_id]} for user #{username}" do
          subject { days_inactive }
          it { should be <= max_inactive_days }
        end
      end
    end

    # Check console password last used
    if user.has_console_password
      password_last_used = user.password_last_used
      if password_last_used
        days_inactive = (Date.today - password_last_used.to_date).to_i

        describe "Console password for user #{username}" do
          subject { days_inactive }
          it { should be <= max_inactive_days }
        end
      end
    end
  end
end

# CIS 1.14: Ensure access keys are rotated every 90 days or less
control 'cis-aws-1-14' do
  impact 0.5
  title 'Ensure access keys are rotated every 90 days or less'
  desc 'Access keys consist of an access key ID and secret access key. They should be rotated to ensure that data cannot be accessed with an old key.'

  tag cis: 'CIS-AWS-1.14'
  tag severity: 'medium'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  max_key_age_days = 90

  aws_iam_users.usernames.each do |username|
    user = aws_iam_user(username)

    user.access_keys.each do |access_key|
      next unless access_key[:active]

      key_age_days = (Date.today - access_key[:created_date].to_date).to_i

      describe "Access key #{access_key[:access_key_id]} for user #{username}" do
        subject { key_age_days }
        it { should be <= max_key_age_days }
      end
    end
  end
end

# CIS 1.16: Ensure IAM policies that allow full "*:*" administrative privileges are not attached
control 'cis-aws-1-16' do
  impact 1.0
  title 'Ensure IAM policies that allow full "*:*" administrative privileges are not attached'
  desc 'IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended that IAM policies that allow full administrative privileges are not created.'

  tag cis: 'CIS-AWS-1.16'
  tag severity: 'critical'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  # Allowed admin policies (like AdministratorAccess for specific roles)
  allowed_admin_policies = input('exempt_admin_policies', value: ['AdministratorAccess'])

  # Check inline policies
  aws_iam_users.usernames.each do |username|
    user = aws_iam_user(username)

    user.inline_policy_names.each do |policy_name|
      policy_doc = user.inline_policy_document(policy_name)

      if has_full_admin_privileges?(policy_doc)
        describe "Inline policy '#{policy_name}' for user #{username}" do
          subject { "Has full admin privileges" }
          it { should_not match /.*/ }
        end
      end
    end
  end

  # Check customer managed policies
  aws_iam_policies.policy_names.each do |policy_name|
    next if allowed_admin_policies.include?(policy_name)

    policy = aws_iam_policy(policy_name)

    if has_full_admin_privileges?(policy.policy)
      describe "Customer managed policy '#{policy_name}'" do
        subject { "Has full admin privileges" }
        it { should_not match /.*/ }
      end
    end
  end
end

# Helper method to check for full admin privileges
def has_full_admin_privileges?(policy_doc)
  return false unless policy_doc && policy_doc['Statement']

  policy_doc['Statement'].any? do |statement|
    statement['Effect'] == 'Allow' &&
    (statement['Action'] == '*' || (statement['Action'].is_a?(Array) && statement['Action'].include?('*'))) &&
    (statement['Resource'] == '*' || (statement['Resource'].is_a?(Array) && statement['Resource'].include?('*')))
  end
end

# CIS 1.20: Ensure IAM Access Analyzer is enabled for all regions
control 'cis-aws-1-20' do
  impact 0.7
  title 'Ensure IAM Access Analyzer is enabled for all regions'
  desc 'IAM Access Analyzer helps identify resources that are shared with an external entity.'

  tag cis: 'CIS-AWS-1.20'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  aws_regions.region_names.each do |region|
    describe aws_accessanalyzer_analyzers(region: region) do
      it { should exist }
    end
  end
end

# CIS AWS Foundations Benchmark - Section 5: Networking
# InSpec Controls

# CIS 5.1: Ensure no NACLs allow ingress from 0.0.0.0/0 to admin ports
control 'cis-aws-5-1' do
  impact 1.0
  title 'Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports'
  desc 'Network ACLs should not allow unrestricted access to SSH (22) or RDP (3389).'

  tag cis: 'CIS-AWS-5.1'
  tag severity: 'critical'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'
  tag section: '5. Networking'

  admin_ports = [22, 3389]

  aws_vpcs.vpc_ids.each do |vpc_id|
    aws_network_acls(vpc_id: vpc_id).network_acl_ids.each do |nacl_id|
      nacl = aws_network_acl(network_acl_id: nacl_id)

      nacl.ingress_rules.each do |rule|
        next unless rule[:action] == 'allow'
        next unless ['0.0.0.0/0', '::/0'].include?(rule[:cidr_block])

        from_port = rule[:port_range][:from] rescue 0
        to_port = rule[:port_range][:to] rescue 65535

        admin_ports.each do |port|
          describe "NACL #{nacl_id} ingress rule #{rule[:rule_number]}" do
            it "should not allow access to port #{port} from 0.0.0.0/0" do
              expect(from_port..to_port).to_not cover(port)
            end
          end
        end
      end
    end
  end
end

# CIS 5.2: Ensure no security groups allow unrestricted ingress to admin ports
control 'cis-aws-5-2' do
  impact 1.0
  title 'Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports'
  desc 'Security groups should not allow unrestricted access to SSH (22) or RDP (3389).'

  tag cis: 'CIS-AWS-5.2'
  tag severity: 'critical'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  admin_ports = [22, 3389]

  aws_security_groups.group_ids.each do |sg_id|
    sg = aws_security_group(group_id: sg_id)

    describe "Security Group #{sg_id} (#{sg.group_name})" do
      admin_ports.each do |port|
        it "should not allow unrestricted ingress to port #{port}" do
          sg.inbound_rules.each do |rule|
            next unless rule[:ip_ranges].any? { |r| ['0.0.0.0/0', '::/0'].include?(r[:cidr_ip]) }

            from_port = rule[:from_port] || 0
            to_port = rule[:to_port] || 65535

            expect(from_port..to_port).to_not cover(port)
          end
        end
      end
    end
  end

  # Summary count
  open_admin_sgs = aws_security_groups.group_ids.select do |sg_id|
    sg = aws_security_group(group_id: sg_id)
    sg.inbound_rules.any? do |rule|
      rule[:ip_ranges].any? { |r| ['0.0.0.0/0', '::/0'].include?(r[:cidr_ip]) } &&
        admin_ports.any? { |port| (rule[:from_port] || 0)..(rule[:to_port] || 65535).to_a.include?(port) }
    end
  end

  describe 'Security groups with open admin ports' do
    subject { open_admin_sgs }
    its('count') { should eq 0 }
  end
end

# CIS 5.3: Ensure default security group restricts all traffic
control 'cis-aws-5-3' do
  impact 0.7
  title 'Ensure the default security group of every VPC restricts all traffic'
  desc 'Default security group should have no ingress or egress rules to enforce explicit rule creation.'

  tag cis: 'CIS-AWS-5.3'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  aws_vpcs.vpc_ids.each do |vpc_id|
    # Find default security group for this VPC
    default_sg = aws_security_groups
      .where(vpc_id: vpc_id)
      .group_ids
      .find { |sg_id| aws_security_group(group_id: sg_id).group_name == 'default' }

    next unless default_sg

    sg = aws_security_group(group_id: default_sg)

    describe "Default Security Group in VPC #{vpc_id}" do
      it 'should have no ingress rules' do
        expect(sg.inbound_rules_count).to eq 0
      end

      it 'should have no egress rules' do
        expect(sg.outbound_rules_count).to eq 0
      end
    end
  end
end

# CIS 5.4: Ensure routing tables for VPC peering are "least access"
control 'cis-aws-5-4' do
  impact 0.5
  title "Ensure routing tables for VPC peering are 'least access'"
  desc 'VPC peering routes should be specific and not use 0.0.0.0/0 destinations.'

  tag cis: 'CIS-AWS-5.4'
  tag severity: 'medium'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  aws_route_tables.route_table_ids.each do |rt_id|
    rt = aws_route_table(route_table_id: rt_id)

    rt.routes.each do |route|
      next unless route[:vpc_peering_connection_id]

      describe "Route table #{rt_id} peering route" do
        it 'should not have 0.0.0.0/0 as destination' do
          expect(route[:destination_cidr_block]).to_not eq '0.0.0.0/0'
        end
      end
    end
  end
end

# CIS 5.5: Ensure no NACLs allow ingress from 0.0.0.0/0 to ports 22 or 3389
control 'cis-aws-5-5' do
  impact 1.0
  title 'Ensure no Network ACLs allow ingress from 0.0.0.0/0 to port 22 or port 3389'
  desc 'Network ACLs must block unrestricted SSH and RDP access.'

  tag cis: 'CIS-AWS-5.5'
  tag severity: 'critical'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  # This is similar to 5.1, checking specifically for SSH and RDP
  aws_network_acls.network_acl_ids.each do |nacl_id|
    nacl = aws_network_acl(network_acl_id: nacl_id)

    describe aws_network_acl(network_acl_id: nacl_id) do
      it 'should not allow SSH from 0.0.0.0/0' do
        dangerous_rules = nacl.ingress_rules.select do |rule|
          rule[:action] == 'allow' &&
            ['0.0.0.0/0', '::/0'].include?(rule[:cidr_block]) &&
            (rule[:port_range][:from]..rule[:port_range][:to]).cover?(22) rescue false
        end
        expect(dangerous_rules).to be_empty
      end

      it 'should not allow RDP from 0.0.0.0/0' do
        dangerous_rules = nacl.ingress_rules.select do |rule|
          rule[:action] == 'allow' &&
            ['0.0.0.0/0', '::/0'].include?(rule[:cidr_block]) &&
            (rule[:port_range][:from]..rule[:port_range][:to]).cover?(3389) rescue false
        end
        expect(dangerous_rules).to be_empty
      end
    end
  end
end

# CIS 5.6: Ensure EC2 Metadata Service only allows IMDSv2
control 'cis-aws-5-6' do
  impact 0.7
  title 'Ensure that EC2 Metadata Service only allows IMDSv2'
  desc 'EC2 instances should require IMDSv2 to protect against SSRF attacks.'

  tag cis: 'CIS-AWS-5.6'
  tag severity: 'high'
  tag standard: 'CIS AWS Foundations Benchmark v1.5.0'

  aws_ec2_instances.instance_ids.each do |instance_id|
    instance = aws_ec2_instance(instance_id)

    describe "EC2 instance #{instance_id}" do
      it 'should require IMDSv2 (http_tokens = required)' do
        metadata_options = instance.metadata_options
        expect(metadata_options.http_tokens).to eq 'required'
      end
    end
  end

  # Summary of non-compliant instances
  imdsv1_instances = aws_ec2_instances.instance_ids.select do |instance_id|
    instance = aws_ec2_instance(instance_id)
    instance.metadata_options.http_tokens != 'required' rescue true
  end

  describe 'EC2 instances allowing IMDSv1' do
    subject { imdsv1_instances }
    its('count') { should eq 0 }
  end
end

# Additional: Ensure no security groups allow all traffic
control 'security-group-no-all-traffic' do
  impact 1.0
  title 'Ensure no security groups allow all traffic from 0.0.0.0/0'
  desc 'Security groups should never allow all traffic from any source.'

  tag severity: 'critical'
  tag best_practice: true

  aws_security_groups.group_ids.each do |sg_id|
    sg = aws_security_group(group_id: sg_id)

    describe "Security Group #{sg_id}" do
      it 'should not allow all traffic from 0.0.0.0/0' do
        all_traffic_rules = sg.inbound_rules.select do |rule|
          rule[:ip_protocol] == '-1' &&
            rule[:ip_ranges].any? { |r| r[:cidr_ip] == '0.0.0.0/0' }
        end
        expect(all_traffic_rules).to be_empty
      end
    end
  end
end

# Additional: Check for unused security groups
control 'security-group-unused' do
  impact 0.3
  title 'Identify unused security groups'
  desc 'Unused security groups should be reviewed and removed if not needed.'

  tag severity: 'low'
  tag best_practice: true

  # This is informational - identify SGs not attached to any ENI
  # In production, you would query ENIs to find unused SGs
  describe 'Security group audit' do
    skip 'Manual review required: Check for security groups not attached to any resource'
  end
end

# Additional: Database ports should not be publicly accessible
control 'security-group-database-ports' do
  impact 0.7
  title 'Ensure database ports are not publicly accessible'
  desc 'Database ports should not be accessible from 0.0.0.0/0.'

  tag severity: 'high'
  tag best_practice: true

  database_ports = [3306, 5432, 1433, 1521, 27017, 6379, 5439]

  aws_security_groups.group_ids.each do |sg_id|
    sg = aws_security_group(group_id: sg_id)

    describe "Security Group #{sg_id}" do
      database_ports.each do |port|
        it "should not allow public access to database port #{port}" do
          open_db_rules = sg.inbound_rules.select do |rule|
            rule[:ip_ranges].any? { |r| r[:cidr_ip] == '0.0.0.0/0' } &&
              ((rule[:from_port] || 0)..(rule[:to_port] || 65535)).cover?(port)
          end
          expect(open_db_rules).to be_empty
        end
      end
    end
  end
end

# PCI-DSS 1.2.1: Restrict traffic to CDE
control 'pci-dss-1-2-1' do
  impact 1.0
  title 'Ensure inbound and outbound traffic to CDE is restricted'
  desc 'Traffic to cardholder data environment must be tightly controlled.'

  tag standard: 'PCI-DSS v4.0'
  tag requirement: '1.2.1'
  tag severity: 'critical'

  # Find PCI-tagged resources
  aws_security_groups.group_ids.each do |sg_id|
    sg = aws_security_group(group_id: sg_id)
    tags = sg.tags rescue {}

    next unless tags['Environment'] == 'PCI' || tags['DataClassification'] == 'PCI'

    describe "PCI Security Group #{sg_id}" do
      it 'should have no public ingress except for web ports' do
        allowed_ports = [443, 80]  # Only HTTPS/HTTP for web-facing

        public_rules = sg.inbound_rules.select do |rule|
          rule[:ip_ranges].any? { |r| r[:cidr_ip] == '0.0.0.0/0' }
        end

        public_rules.each do |rule|
          from_port = rule[:from_port] || 0
          to_port = rule[:to_port] || 0
          ports_in_rule = (from_port..to_port).to_a

          expect(ports_in_rule - allowed_ports).to be_empty,
                 "Unauthorized public port access: #{ports_in_rule - allowed_ports}"
        end
      end
    end
  end
end

#!/bin/bash

# MIT No Attribution
# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#Configure default region for the AWS cli
aws configure set region {RegionName}

#Crate the EnginFrame administrator user
adduser efadmin

#Retrieve the efadmin password from secret manager
efadmin_password=$(aws secretsmanager get-secret-value --secret-id {arn_secret_password} --query SecretString --output text | awk -F'"' '{{ print $4 }}')

#Configure the password for the efadmin user
printf "$efadmin_password" | passwd efadmin --stdin

#Install some required packages
yum -y install python2-pip 

#Retrieve from parameter store the EnginFrame hostname
ef_hostname=$(aws ssm get-parameter --name EnginFrameHost --output text --query Parameter.Value)
#Retrieve from parameter store the DCVSM broker certificate
dcvsm_certificate=$(aws ssm get-parameter --name DCVSMCertificate --output text --query Parameter.Value)

#Configure the DCV configuration file
sed -i '/^\[security\]/a administrators=["dcvsmagent"]' /etc/dcv/dcv.conf
sed -i '/^\[security\]/a ca-file="/etc/dcv-session-manager-agent/broker_cert.pem"' /etc/dcv/dcv.conf
sed -i "/^\[security\]/a auth-token-verifier=\"https://$ef_hostname:8445/agent/validate-authentication-token\"" /etc/dcv/dcv.conf
sed -i "/^\[connectivity\]/a web-url-path=\"/$(hostname -s)\"" /etc/dcv/dcv.conf

#Configure the DCVSM configuration file
sed -i "s/^broker_host =.*$/broker_host = '$ef_hostname'/" /etc/dcv-session-manager-agent/agent.conf
sed -i "/^\[agent\]/a ca_file = '/etc/dcv-session-manager-agent/broker_cert.pem'" /etc/dcv-session-manager-agent/agent.conf



#Save the retrieved certificate
echo "$dcvsm_certificate" > /etc/dcv-session-manager-agent/broker_cert.pem

#Start DCV
systemctl restart dcvserver
systemctl enable dcvserver

#Start DCV session manager
systemctl restart dcv-session-manager-agent.service
systemctl enable dcv-session-manager-agent.service

#Retrieve the InstanceID
MyInstID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)

#Retrieve the logical ID of the resource
ASGLOGICALID=$(aws ec2 describe-instances --instance-ids $MyInstID --query "Reservations[].Instances[].Tags[?Key=='aws:cloudformation:logical-id'].Value" --output text)

pip install https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.tar.gz

#Send the signal to the Cloudformation Stack
/opt/aws/bin/cfn-signal -e $? --stack {StackName} --resource $ASGLOGICALID --region {RegionName}
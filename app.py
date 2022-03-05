#!/usr/bin/env python3

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

from aws_cdk import (
    App
)
from constructs import Construct

from dcv_session_manager_infrastructure.dcv_session_manager_infrastructure_stack import DcvSessionManagerInfrastructureStack


CONFIG = {
   "region": "<region>", #AWS Region
   "account": "<account>", #AWS account number
   "ec2_type_enginframe": "t2.2xlarge", #EnginFrame instance type
   "ec2_type_dcv_linux": "g4dn.xlarge", #DCV Linux instance type (x86 instances only)
   "ec2_type_dcv_windows": "g4dn.xlarge", #DCV Windows instance type (x86 instances only)
   "linux_dcv_number": 1, #Number of DCV Linux nodes
   "windows_dcv_number": 1, #Number of DCV Windows nodes
   "arn_efadmin_password": "<arn_secret>", # ARN of the secret that contains the efadmin password
   "key_name": "<key_name>", #SSH key name that you already have in your account
   "ebs_engingframe_size": 50, #EBS size for EnginFrame
   "ebs_dcv_linux_size": 50, #EBS size for DCV linux
   "ebs_dcv_windows_size": 50 #EBS size for DCV windows
}

app = App()
# Region and Account are required to retrieve the image to use for the instances
DcvSessionManagerInfrastructureStack(app, "dcv-session-manager-infrastructure", config=CONFIG, env={"region": CONFIG['region'], "account": CONFIG['account']})

app.synth()

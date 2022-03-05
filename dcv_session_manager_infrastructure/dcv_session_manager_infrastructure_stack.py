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

import base64

from aws_cdk import (
    Aws,
    CfnOutput,
    CustomResource,
    Duration,
    Stack,
    aws_autoscaling as autoscaling,
    aws_ec2 as ec2,
    aws_elasticloadbalancingv2 as elbv2,
    aws_iam as iam,
    aws_ssm as ssm,
    aws_lambda as _lambda,
    custom_resources as cr,
    aws_logs as logs,
    aws_certificatemanager as acm,
    aws_s3_assets as assets
)
from constructs import Construct

# Class used to build the infrastructure


class DcvSessionManagerInfrastructureStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, config: list, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Copy the required files to S3
        closing_hook = assets.Asset(
            self, "ClosingHook", path='scripts/alb.session.closing.hook.sh')
        starting_hook = assets.Asset(
            self, "StartingHook", path='scripts/alb.session.starting.hook.sh')
        interactive_builtin_linux_desktop = assets.Asset(
            self, "LinuxDesktop", path='scripts/interactive_builtin_linux_desktop.xml')
        interactive_builtin_windows_desktop = assets.Asset(
            self, "WindowsDesktop", path='scripts/interactive_builtin_windows_desktop.xml')

        # VPC creation
        vpc = ec2.Vpc(self, "VPC",
                      max_azs=2,
                      cidr="10.0.0.0/16",
                      subnet_configuration=[ec2.SubnetConfiguration(
                          subnet_type=ec2.SubnetType.PUBLIC,
                          name="Public",
                          cidr_mask=24
                      )])

        # Create ALB
        alb_security_group, lb_enginframe = self.create_alb(vpc)

        # Create the EF and DCV security groups
        ef_security_group, dcv_security_group = self.create_security_groups(
            vpc, alb_security_group)

        # Create the SSM parameters that will contain the hostname of the EnginFrame instance and the certificate of the DCVSM broker
        ef_nodename_parameter, dcvsm_certificate = self.create_parameters()

        # ROLES
        role_ef = self.create_ef_role(
            ef_nodename_parameter, dcvsm_certificate, config, closing_hook, starting_hook, interactive_builtin_linux_desktop, interactive_builtin_windows_desktop)
        role_dcv = self.create_dcv_role(
            ef_nodename_parameter, dcvsm_certificate, config)

        # create EF and DCV instances
        asg_enginframe = self.create_enginframe(
            config, lb_enginframe, vpc, role_ef, ef_security_group, closing_hook, starting_hook, interactive_builtin_linux_desktop, interactive_builtin_windows_desktop)
        asg_dcv_linux = self.create_dcv_linux(
            config, vpc, role_dcv, dcv_security_group)
        asg_dcv_windows = self.create_dcv_windows(
            config, vpc, role_dcv, dcv_security_group)

        # Create Lambda
        lambda_function = self.create_lambda(lb_enginframe)

        # Get the ACM certificate ARM from the lambda function
        certificate_arn = lambda_function.get_att_string("ACMCertificateArn")
        certificate = acm.Certificate.from_certificate_arn(
            self, 'Certificate', certificate_arn)

        # ALB listener
        listener_enginframe = lb_enginframe.add_listener(
            "Listener", port=443, certificates=[certificate])
        listener_enginframe.add_targets(
            "Target", port=8443, targets=[asg_enginframe])
        listener_enginframe.connections.allow_default_port_from_any_ipv4(
            "Open to the world")

        # ASG dependency
        asg_dcv_linux.node.add_dependency(asg_enginframe)
        asg_dcv_windows.node.add_dependency(asg_enginframe)

        # Return the ALB url
        CfnOutput(self, "EnginFramePortalURL",
                  value="https://"+lb_enginframe.load_balancer_dns_name)

    # Function to create the ALB

    def create_alb(self, vpc):
        # ALB Security group
        alb_security_group = ec2.SecurityGroup(self, "ALBSecurityGroup",
                                               vpc=vpc,
                                               description="ALB SecurityGroup ",
                                               security_group_name="ALB SecurityGroup",
                                               allow_all_outbound=True,
                                               )
        # Allow 443 access to the ALB
        alb_security_group.add_ingress_rule(ec2.Peer.ipv4(
            '0.0.0.0/0'), ec2.Port.tcp(443), "allow http access")

        # Create ALB
        lb_enginframe = elbv2.ApplicationLoadBalancer(
            self, "EFLB",
            vpc=vpc,
            internet_facing=True,
            security_group=alb_security_group)

        return alb_security_group, lb_enginframe

    # Function to create the required SSM parameters
    def create_parameters(self):
        # Parameter that will contain the hostname of the EnginFrame instance
        ef_nodename_parameter = ssm.StringParameter(self, "EnginFrame host",
                                                    allowed_pattern=".*",
                                                    description="EnginFrame host",
                                                    parameter_name="EnginFrameHost",
                                                    string_value="dummy")

        # Parameter that will contain the certificate of the DCVSM broker
        dcvsm_certificate = ssm.StringParameter(self, "DCVSM certificate",
                                                allowed_pattern=".*",
                                                description="DCVSM certificate",
                                                parameter_name="DCVSMCertificate",
                                                string_value="dummy")
        return ef_nodename_parameter, dcvsm_certificate

    # Function to create the ASG
    def create_asg(self, asg_type, vpc, instance_type, ami, userdata, role, key_name, capacity, security_group, device_name, volume_size):
        # ASG
        asg = autoscaling.AutoScalingGroup(
            self,
            "ASG_"+asg_type,
            auto_scaling_group_name="ASG_"+asg_type,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            instance_type=ec2.InstanceType(instance_type),
            machine_image=ami,
            user_data=userdata,
            role=role,
            key_name=key_name,
            desired_capacity=capacity,
            min_capacity=capacity,
            max_capacity=capacity,
            security_group=security_group,
            signals=autoscaling.Signals.wait_for_count(
                capacity, timeout=Duration.minutes(30)),
            block_devices=[
                autoscaling.BlockDevice(
                    device_name=device_name,
                    volume=autoscaling.BlockDeviceVolume.ebs(
                        volume_type=autoscaling.EbsDeviceVolumeType.GP2,
                        volume_size=volume_size,
                        delete_on_termination=True
                    )
                )]
        )
        return asg

    # Function used to define the EnginFrame instance
    def create_enginframe(self, config, lb_enginframe, vpc, role_ef, ef_security_group, closing_hook, starting_hook, interactive_builtin_linux_desktop, interactive_builtin_windows_desktop):
        # Userdata of the instances
        data_enginframe = open("userdata/enginframe.sh", "rb").read()
        enginframe_userdata = ec2.UserData.for_linux()
        # Change some placeholders inside the userdata of the instances
        data_enginframe_format = str(data_enginframe, 'utf-8').format(arn_secret_password=config['arn_efadmin_password'],
                                                                      StackName=Aws.STACK_NAME,
                                                                      RegionName=Aws.REGION,
                                                                      ALB_DNS_NAME=lb_enginframe.load_balancer_dns_name,
                                                                      closing_hook=closing_hook.s3_object_url,
                                                                      starting_hook=starting_hook.s3_object_url,
                                                                      interactive_builtin_linux_desktop=interactive_builtin_linux_desktop.s3_object_url,
                                                                      interactive_builtin_windows_desktop=interactive_builtin_windows_desktop.s3_object_url)
        # Add the userdata to the instances
        enginframe_userdata.add_commands(data_enginframe_format)
        # Search for the latest AMIs for the instances
        linux_ami_enginframe = ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
                                                    edition=ec2.AmazonLinuxEdition.STANDARD,
                                                    virtualization=ec2.AmazonLinuxVirt.HVM,
                                                    storage=ec2.AmazonLinuxStorage.GENERAL_PURPOSE,
                                                    cpu_type=ec2.AmazonLinuxCpuType.X86_64
                                                    )
        # EnginFrame instance ASG
        asg_enginframe = self.create_asg("Enginframe", vpc, config['ec2_type_enginframe'], linux_ami_enginframe, enginframe_userdata,
                                         role_ef, config['key_name'], 1, ef_security_group, "/dev/xvda", config['ebs_engingframe_size'])

        return asg_enginframe

    # Function used to define the DCV linux instance

    def create_dcv_linux(self, config, vpc, role_dcv, dcv_security_group):
        # Userdata of the instances
        data_dcv_linux = open("userdata/dcv_linux.sh", "rb").read()
        dcv_linux_userdata = ec2.UserData.for_linux()
        # Change some placeholders inside the userdata of the instances
        data_dcv_linux_format = str(data_dcv_linux, 'utf-8').format(arn_secret_password=config['arn_efadmin_password'],
                                                                    StackName=Aws.STACK_NAME,
                                                                    RegionName=Aws.REGION)
        # Add the userdata to the instances
        dcv_linux_userdata.add_commands(data_dcv_linux_format)
        # Search for the latest AMIs for the instances
        linux_ami_dcv_linux = ec2.MachineImage.lookup(
            name="DCV-AmazonLinux2-x86_64-*-NVIDIA-*",
            owners=["amazon"]
        )
        # Linux DCV instances ASG
        asg_dcv_linux = self.create_asg("dcv_linux", vpc, config['ec2_type_dcv_linux'], linux_ami_dcv_linux, dcv_linux_userdata,
                                        role_dcv, config['key_name'], config['linux_dcv_number'], dcv_security_group, "/dev/xvda", config['ebs_dcv_linux_size'])

        return asg_dcv_linux

    # Function used to define the DCV Windows instance
    def create_dcv_windows(self, config, vpc, role_dcv, dcv_security_group):
        # Userdata of the instances
        data_dcv_windows = open("userdata/dcv_windows.ps", "rb").read()
        dcv_windows_userdata = ec2.UserData.for_windows()
        # Change some placeholders inside the userdata of the instances
        data_dcv_windows_format = str(data_dcv_windows, 'utf-8').format(arn_secret_password=config['arn_efadmin_password'],
                                                                        StackName=Aws.STACK_NAME,
                                                                        RegionName=Aws.REGION)
        # Add the userdata to the instances
        dcv_windows_userdata.add_commands(data_dcv_windows_format)
        # Search for the latest AMIs for the instances
        windows_ami_dcv_linux = ec2.MachineImage.lookup(
            name="DCV-Windows*NVIDIA*",
            owners=["amazon"]
        )
        # Windows DCV instances ASG
        asg_dcv_windows = self.create_asg("dcv_windows", vpc, config['ec2_type_dcv_linux'], windows_ami_dcv_linux, dcv_windows_userdata,
                                          role_dcv, config['key_name'], config['windows_dcv_number'], dcv_security_group, "/dev/sda1", config['ebs_dcv_windows_size'])

        return asg_dcv_windows

    # Function used to create the EnginFrame required role
    def create_ef_role(self, ef_nodename_parameter, dcvsm_certificate, config, closing_hook, starting_hook, interactive_builtin_linux_desktop, interactive_builtin_windows_desktop):
        # Instances Role
        role_ef = iam.Role(
            self, "EF_ROLE", assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"))
        # Allow console access with SSM
        role_ef.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name(
            "AmazonSSMManagedInstanceCore"))
        # Allow to the EF node to modify the SSM parameters
        role_ef.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "ssm:PutParameter",
                    "ssm:GetParameter"
                ],
                resources=[ef_nodename_parameter.parameter_arn,
                           dcvsm_certificate.parameter_arn],
            )
        )
        # Allow to the EF node to download the required files from S3
        role_ef.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "s3:GetObject"
                ],
                resources=["arn:aws:s3:::" + closing_hook.s3_bucket_name + "/" + closing_hook.s3_object_key,
                           "arn:aws:s3:::" + starting_hook.s3_bucket_name +
                           "/" + starting_hook.s3_object_key,
                           "arn:aws:s3:::" + interactive_builtin_linux_desktop.s3_bucket_name +
                           "/" + interactive_builtin_linux_desktop.s3_object_key,
                           "arn:aws:s3:::" + interactive_builtin_windows_desktop.s3_bucket_name + "/" + interactive_builtin_windows_desktop.s3_object_key],
            )
        )
        # Allow to retrieve the efadmin password
        role_ef.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "secretsmanager:GetSecretValue"
                ],
                resources=[config['arn_efadmin_password']],
            )
        )
        # Allow to describe the instances
        role_ef.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "ec2:DescribeInstances"
                ],
                resources=["*"],
            )
        )
        # Allow the EF node to modify the loadbalancer
        role_ef.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "elasticloadbalancing:*"
                ],
                resources=["*"],
            )
        )

        return role_ef

    # Function used to create the DCV required role

    def create_dcv_role(self, ef_nodename_parameter, dcvsm_certificate, config):
        # Instances Role
        role_dcv = iam.Role(
            self, "DCV_ROLE", assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"))
        # Allow console access with SSM
        role_dcv.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name(
            "AmazonSSMManagedInstanceCore"))
        # Allow the DCV nodes to access the parameters
        role_dcv.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "ssm:GetParameter"
                ],
                resources=[ef_nodename_parameter.parameter_arn,
                           dcvsm_certificate.parameter_arn],
            )
        )
        # Allow to retrieve the efadmin password
        role_dcv.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "secretsmanager:GetSecretValue"
                ],
                resources=[config['arn_efadmin_password']],
            )
        )
        # Allow to describe the instances
        role_dcv.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "ec2:DescribeInstances"
                ],
                resources=["*"],
            )
        )

        return role_dcv

    # Function to create the EF and DCV security groups

    def create_security_groups(self, vpc, alb_security_group):
        ef_security_group = ec2.SecurityGroup(self, "EFSecurityGroup",
                                              vpc=vpc,
                                              description="SecurityGroup for EF ",
                                              security_group_name="EF SecurityGroup",
                                              allow_all_outbound=True,
                                              )
        dcv_security_group = ec2.SecurityGroup(self, "DCVSecurityGroup",
                                               vpc=vpc,
                                               description="SecurityGroup for DCV ",
                                               security_group_name="DCV SecurityGroup",
                                               allow_all_outbound=True,
                                               )
        ef_security_group.add_ingress_rule(
            alb_security_group, ec2.Port.tcp(8443), "allow http access from the vpc")
        ef_security_group.add_ingress_rule(
            dcv_security_group, ec2.Port.all_traffic(), "allow local access ")
        dcv_security_group.add_ingress_rule(
            alb_security_group, ec2.Port.tcp(8443), "allow dcv access ")
        dcv_security_group.add_ingress_rule(
            ef_security_group, ec2.Port.all_traffic(), "allow local access ")

        return ef_security_group, dcv_security_group

    # Function to create Lambda

    def create_lambda(self, lb_enginframe):
        # Lambda role
        lambda_role = iam.Role(
            self, id="LambdaRole", assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "acm:ImportCertificate",
                    "acm:ListCertificates",
                    "acm:DeleteCertificate",
                    "acm:DescribeCertificate",
                    "logs:CreateLogStream",
                    "logs:CreateLogGroup",
                    "logs:PutLogEvents"
                ],
                resources=["*"],
            )
        )

        # Lambda to create the ALB https certificate
        lambda_cert = _lambda.Function(self, "lambda_create_cert",
                                       runtime=_lambda.Runtime.PYTHON_3_7,
                                       handler="cert.lambda_handler",
                                       code=_lambda.Code.from_asset(
                                           "./lambda"),
                                       timeout=Duration.seconds(600),
                                       role=lambda_role)

        lambda_cs = CustomResource(
            self, "Resource1",
            service_token=lambda_cert.function_arn,
            properties={
                "LoadBalancerDNSName": lb_enginframe.load_balancer_dns_name
            }
        )
        return lambda_cs

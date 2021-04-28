
Blog post link: https://aws.amazon.com/blogs/hpc/a-vdi-solution-with-enginframe-and-nice-dcv-session-manager-built-with-aws-cdk/

# A VDI solution with EnginFrame and DCV Session Manager built with AWS CDK

The architecture proposed in this blog post is designed to simplify the process of setting up and running technical and scientific applications that take advantage of the power, scale, and flexibility of the AWS Cloud. You can set up a fully functional Linux and Windows VDI infrastructure and then access it through a simple web-based user interface.

The solution uses three main components:

NICE EnginFrame (https://download.enginframe.com/) is an advanced web front-end for accessing technical and scientific applications in the Cloud and enables HPC users to get the job done faster, without facing the complexity of the underlying computing infrastructure.

NICE DCV (https://aws.amazon.com/hpc/dcv/) is a high-performance remote display protocol that eliminates the need to ship output files to client devices and provides a smooth and bandwidth-efficient experience to stream HPC 3D graphics remotely.

NICE DCV Session Manager (https://docs.aws.amazon.com/dcv/latest/sm-admin/what-is-sm.html) creates and manages the lifecycle of NICE DCV sessions across a fleet of NICE DCV servers.

The solution is deployed using AWS CDK (https://docs.aws.amazon.com/cdk/latest/guide/home.html)  with the Python (https://docs.aws.amazon.com/cdk/latest/guide/work-with-cdk-python.html) 3 language. This technology enables to create and provision AWS infrastructure deployments predictably and repeatedly  with a familiar programming language like Python.


Inside the repo:

 * app.py contains the configuration variables used to deploy the environment. Before the deployment, you need to customize it with the required configurations. Be sure to modify <region> and <account> to match the values for your account. <key_name> is your Amazon EC2 key pair. <arn_secret> is the arn of the secret created in the previous step. The additional parameters can be modified depending your requirements.
 * dcv_session_manager_infrastructure/dcv_session_manager_infrastructure_stack.py contains the main functions to deploy all the required resources.
 * lambda/cert.py is the lambda function used to create the Application Load Balancer  certificate. 
 * The userdata folder contains the scripts used to configure the EnginFrame and DCV nodes. 




The following commands can be used for the deployment:

```
$ python3 -m venv .venv
```

After the init process completes and the virtualenv is created, you can use the following
step to activate your virtualenv.

```
$ cd dcv-session-manager-infrastructure
$ python3 -m venv .env
$ source .env/bin/activate
$ python3 -m pip install -r requirements.txt
$ cdk bootstrap aws://<account>/<region>
$ cdk deploy
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.


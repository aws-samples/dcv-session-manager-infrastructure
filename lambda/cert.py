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


import boto3
import os
import subprocess
import time
import json
import logging
import urllib.request, urllib.parse

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

#function to send the response to the cloudformation stack
def send_response(event, context, response_status, response_data):
    '''Send a resource manipulation status response to CloudFormation'''
    response_body = json.dumps({
        "Status": response_status,
        "Reason": "See the details in CloudWatch Log Stream: " + context.log_stream_name,
        "PhysicalResourceId": context.log_stream_name,
        "StackId": event['StackId'],
        "RequestId": event['RequestId'],
        "LogicalResourceId": event['LogicalResourceId'],
        "Data": response_data
    })
    
    response_body_bytes = response_body.encode('utf-8')

    LOGGER.info('ResponseURL: %s', event['ResponseURL'])
    LOGGER.info('ResponseBody: %s', response_body)

    opener = urllib.request.build_opener(urllib.request.HTTPHandler)
    request = urllib.request.Request(event['ResponseURL'], data=response_body_bytes)
    request.add_header('Content-Type', 'application/json; charset=utf-8')
    request.add_header('Content-Length', len(response_body_bytes))
    request.get_method = lambda: 'PUT'
    response = opener.open(request)
    LOGGER.info("Status code: %s", response.getcode())
    LOGGER.info("Status message: %s", response.msg)
    
    

def lambda_handler(event, context):
    output = {}
    #Create the ACM client
    client_acm = boto3.client('acm')
    #Name of the certificate
    LoadBalancerDNSName = event['ResourceProperties']['LoadBalancerDNSName']
    LoadBalancerDNSNameCert = LoadBalancerDNSName.split('.', 1)[0]+".cert"
    #Section related to the creation of the stack
    if event['RequestType'] == 'Create':
      #Create the private key
      subprocess.check_output("openssl genrsa 2048 > /tmp/server.key", shell=True)
      try:
        #Create the certificate
        config = open('/tmp/openssl.cnf', 'w+')
        config.write('[req]\nprompt=no\ndistinguished_name=enginframe\nx509_extensions=v3_req\n')
        config.write('[enginframe]\nC=US\nST=WA\nL=Seattle\nO=AWS WWSO\nOU=HPC\nCN=EnginFrame\n')
        config.write('[v3_req]\nkeyUsage=keyEncipherment,dataEncipherment,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=@alt_names\n')
        config.write('[alt_names]\nDNS.1={}\n'.format(LoadBalancerDNSName))
        config.close()
        subprocess.check_output("openssl req -new -x509 -sha1 -nodes -days 3650  -key /tmp/server.key -config /tmp/openssl.cnf > /tmp/server.crt", shell=True)
        os.remove('/tmp/openssl.cnf')
        key = (open("/tmp/server.key","r")).read()
        crt = (open("/tmp/server.crt","r")).read()
      except Exception as e:
        LOGGER.info('Error: %s', e)
        send_response(event, context, "FAILED", output)
      try:
        #import the certificate to ACM
        response = client_acm.import_certificate(Certificate=crt, PrivateKey=key)
        time.sleep(30)
        #Save the certificate arn
        output['ACMCertificateArn'] = response['CertificateArn']
        LOGGER.info('Output: %s', output)
        #return the certificate arn to the stack
        send_response(event, context, "SUCCESS", output)

      except Exception as e:
        LOGGER.info('Error: %s', e)
        send_response(event, context, "FAILED", output)
    #Section related to the deletion of the stack
    elif event['RequestType'] == 'Delete':
      #check the existing certificates
      check_existing = client_acm.list_certificates(CertificateStatuses=['ISSUED'])
      try:
        #Retrieve the certificate and delete it
        for cert in check_existing['CertificateSummaryList']:
            if LoadBalancerDNSName == cert['DomainName']:
              in_use = 1
              LOGGER.info('Found cert: %s', LoadBalancerDNSName)
              while in_use >= 1:
                LOGGER.info('Waiting release')
                time.sleep(5)
                certificate_details = client_acm.describe_certificate(CertificateArn=cert['CertificateArn'])
                cert_usage = certificate_details['Certificate']['InUseBy']
                in_use = len(cert_usage)
              LOGGER.info('Deleting certificate: %s', cert['CertificateArn'])
              client_acm.delete_certificate(CertificateArn=cert['CertificateArn'])
              send_response(event, context, "SUCCESS", output)
      except Exception as e:
        LOGGER.info('Error: %s', e)
        send_response(event, context, "FAILED", output)
      
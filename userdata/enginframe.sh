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

export NICE_ROOT="/opt/nice"

#Crate the EnginFrame administrator user
adduser efadmin

#Create the EnginFrame service user
adduser efnobody

#Retrieve the efadmin password from secret manager
efadmin_password=$(aws secretsmanager get-secret-value --secret-id {arn_secret_password} | grep "SecretString" | sed 's/\\//g' | awk -F'"' '{{ print $7 }}')

#Configure the password for the efadmin user
printf "$efadmin_password" | passwd efadmin --stdin

#Install some required packages
yum -y install java-1.8.0-openjdk.x86_64 curl wget python2-pip

#EnginFrame Download URL
ef_download_url="https://dn3uclhgxk1jt.cloudfront.net/enginframe/packages/enginframe-latest.jar"

wget "$ef_download_url"

ef_jar=$(ls *.jar)

#Java bin Path
java_bin=$(readlink /etc/alternatives/java | sed 's/\/bin\/java//')

#Hostname of the node
ef_hostname=$(hostname -s)

#Create the file used for the EnginFrame unattended installation
cat <<EOF > efinstall.config

efinstall.config.version = 1.0
ef.accept.eula = true
nice.root.dir.ui = /opt/nice
kernel.java.home = $java_bin
ef.spooler.dir = /opt/nice/enginframe/spoolers
ef.repository.dir = /opt/nice/enginframe/repository
ef.sessions.dir = /opt/nice/enginframe/sessions
ef.data.root.dir = /opt/nice/enginframe/data
ef.logs.root.dir = /opt/nice/enginframe/logs
ef.temp.root.dir = /opt/nice/enginframe/tmp
ef.product = PRO
kernel.agent.on.same.machine = true
kernel.agent.rmi.port = 9999
kernel.agent.rmi.bind.port = 9998
kernel.ef.admin.user = efadmin
kernel.server.tomcat.https = true
kernel.ef.tomcat.user = efnobody
kernel.ef.root.context = enginframe
kernel.tomcat.https.port = 8443
kernel.tomcat.shutdown.port = 8005
kernel.server.tomcat.https.ef.hostname = $ef_hostname
kernel.ef.db = derby
kernel.ef.derby.db.port = 1527
kernel.start_enginframe_at_boot = true
demo.install = true
default.auth.mgr = pam
pam.service = system-auth
pam.user =
ef.delegate.dcvsm = true
dcvsm.oauth2.url = https\://$ef_hostname\:8446/oauth2/token
dcvsm.oauth2.id =
dcvsm.broker.url = https\://$ef_hostname\:8446/
dcvsm.no.strict.tls = false
intro-targets = component_enginframe,component_kernel,component_applets,component_parser,component_http,component_pam,component_ldap,component_activedirectory,component_rss,component_lsf,component_pbs,component_torque,component_sge,component_slurm,component_awsbatch,component_dcvsm,component_demo,component_neutro,component_vdi,component_applications,component_service-manager,component_user-group-manager,component_enginframe_finalizer,
progress-targets = cleanuptarget,
EOF

#Install EnginFrame
java -jar "$ef_jar" --text --batch

echo "EF_GRID_MANAGERS=\"dcvsm\"" > /opt/nice/enginframe/conf/plugins/grid/grid.conf 

#Session manager broker download URL
dcvsmb_download_url="https://d1uj6qtbmh3dt5.cloudfront.net/nice-dcv-session-manager-broker-el7.noarch.rpm"

wget "$dcvsmb_download_url"

dcvsmb_rpm=$(ls *.rpm)

#Install Java 11 requirement
amazon-linux-extras install java-openjdk11 -y

#Install DCVSM broker
yum install -y "$dcvsmb_rpm"

# fix java version on startup script and cli
sed -i "s#^java#/etc/alternatives/jre_11/bin/java#" /usr/share/dcv-session-manager-broker/bin/dcv-session-manager-broker.sh
sed -i "s# java # /etc/alternatives/jre_11/bin/java #g" /usr/bin/dcv-session-manager-broker
sed -i "s|^# broker-java-home =|broker-java-home =/etc/alternatives/jre_11|" /etc/dcv-session-manager-broker/session-manager-broker.properties

# switch broker to 8446 since 8443 is used by EnginFrame
sed -i 's/client-to-broker-connector-https-port = .*$/client-to-broker-connector-https-port = 8446/' \
        /etc/dcv-session-manager-broker/session-manager-broker.properties
    
#Start DCVSM broker
systemctl enable dcv-session-manager-broker
systemctl start dcv-session-manager-broker

#Wait the creation of the certificate
while [ ! -f /var/lib/dcvsmbroker/security/dcvsmbroker_ca.pem ]
do
  sleep 2
done

dcvsm_certificate=$(cat /var/lib/dcvsmbroker/security/dcvsmbroker_ca.pem)

#Add the certificate to Parameter store
aws ssm put-parameter --name "DCVSMCertificate" --value "$dcvsm_certificate" --allowed-pattern '' --overwrite

sleep 60

#Register EnginFrame as client to the DCVSM broker
dcv-session-manager-broker register-api-client --client-name EnginFrame > /tmp/ef_client_reg

#Retrieve the generated credentials
client_id=$(cat /tmp/ef_client_reg | sed -n 's/^[ \t]*client-id:[ \t]*//p')
client_pw=$(cat /tmp/ef_client_reg | sed -n 's/^[ \t]*client-password:[ \t]*//p')

#Configure the EnginFrame variables required to communicate with DCVSM
sed -i "s/^DCVSM_CLUSTER_dcvsm_cluster1_AUTH_ID=.*$/DCVSM_CLUSTER_dcvsm_cluster1_AUTH_ID=$client_id/" \
        $NICE_ROOT/enginframe/conf/plugins/dcvsm/clusters.props
sed -i "s/^DCVSM_CLUSTER_dcvsm_cluster1_AUTH_PASSWORD=.*$/DCVSM_CLUSTER_dcvsm_cluster1_AUTH_PASSWORD=$client_pw/" \
        $NICE_ROOT/enginframe/conf/plugins/dcvsm/clusters.props
sed -i "s/^DCVSM_CLUSTER_dcvsm_cluster1_AUTH_ENDPOINT=.*$/DCVSM_CLUSTER_dcvsm_cluster1_AUTH_ENDPOINT=https:\/\/$(hostname):8446\/oauth2\/token/" \
        $NICE_ROOT/enginframe/conf/plugins/dcvsm/clusters.props
sed -i "s/^DCVSM_CLUSTER_dcvsm_cluster1_SESSION_MANAGER_ENDPOINT=.*$/DCVSM_CLUSTER_dcvsm_cluster1_SESSION_MANAGER_ENDPOINT=https:\/\/$(hostname):8446/" \
        $NICE_ROOT/enginframe/conf/plugins/dcvsm/clusters.props

source "$NICE_ROOT/enginframe/conf/enginframe.conf"


# add dcvsm certificate to Java keystore
openssl x509 -in /var/lib/dcvsmbroker/security/dcvsmbroker_ca.pem -inform pem \
        -out /tmp/dcvsmbroker_ca.der -outform der
keytool -importcert -alias dcvsm \
            -keystore "$JAVA_HOME/lib/security/cacerts" \
            -storepass changeit \
            -noprompt \
            -file /tmp/dcvsmbroker_ca.der
            
EF_VERSION=$(cat $NICE_ROOT/enginframe/current-version | awk -F'=' '{{print $2}}')

#Create the EnginFrame hook required to add the ALB rules entries for the DCV sessions. 
aws s3 cp {starting_hook} $NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/interactive/bin/alb.session.starting.hook.sh
sed -i "s/@ALB_DNS_NAME@/{ALB_DNS_NAME}/" $NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/interactive/bin/alb.session.starting.hook.sh
sed -i "s/@RegionName@/{RegionName}/" $NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/interactive/bin/alb.session.starting.hook.sh

#Create the EnginFrame hook required to remove the ALB rules entries for the DCV sessions.
aws s3 cp {closing_hook} $NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/interactive/bin/alb.session.closing.hook.sh
sed -i "s/@ALB_DNS_NAME@/{ALB_DNS_NAME}/" $NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/interactive/bin/alb.session.closing.hook.sh
sed -i "s/@RegionName@/{RegionName}/" $NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/interactive/bin/alb.session.closing.hook.sh


chmod +x $NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/interactive/bin/alb.session.closing.hook.sh
chmod +x $NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/interactive/bin/alb.session.starting.hook.sh

#Publish the linux service in EnginFrame
#Configure the linux service in EnginFrame
sed -i 's/<ef:metadata attribute="VDI_REMOTE">.*$/<ef:metadata attribute="VDI_REMOTE">dcv2sm<\/ef:metadata>\n<ef:metadata attribute="VDI_CLUSTER">dcvsm_cluster1:dcvsm<\/ef:metadata>/' \
        $NICE_ROOT/enginframe/data/plugins/vdi/services/catalog/interactive_builtin_linux_desktop/WEBAPP/service.xml
aws s3 cp {interactive_builtin_linux_desktop} $NICE_ROOT/enginframe/data/plugins/vdi/services/published/interactive_builtin_linux_desktop.xml

#Configure the windows service EnginFrame
sed -i 's/<ef:metadata attribute="VDI_REMOTE">.*$/<ef:metadata attribute="VDI_REMOTE">dcv2sm<\/ef:metadata>\n<ef:metadata attribute="VDI_CLUSTER">dcvsm_cluster1:dcvsm<\/ef:metadata>/' \
        $NICE_ROOT/enginframe/data/plugins/vdi/services/catalog/interactive_builtin_windows_desktop/WEBAPP/service.xml
aws s3 cp {interactive_builtin_windows_desktop}  $NICE_ROOT/enginframe/data/plugins/vdi/services/published/interactive_builtin_windows_desktop.xml

#Configure EnginFrame to use the hooks         
echo "INTERACTIVE_SESSION_STARTING_HOOK=$NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/interactive/bin/alb.session.starting.hook.sh" >> $NICE_ROOT/enginframe/conf/plugins/interactive/interactive.efconf
echo "INTERACTIVE_SESSION_CLOSING_HOOK=$NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/interactive/bin/alb.session.closing.hook.sh" >> $NICE_ROOT/enginframe/conf/plugins/interactive/interactive.efconf

#Start EnginFrame           
systemctl start enginframe

#Add the EnginFrame hostname to parameter store
aws ssm put-parameter --name "EnginFrameHost" --value "$(hostname)" --overwrite

#Retrieve the InstanceID
MyInstID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)

#Retrieve the logical ID of the resource
ASGLOGICALID=$(aws ec2 describe-instances --instance-ids $MyInstID --query "Reservations[].Instances[].Tags[?Key=='aws:cloudformation:logical-id'].Value" --output text)


pip install https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.tar.gz

#Send the signal to the Cloudformation Stack
/opt/aws/bin/cfn-signal -e $? --stack {StackName} --resource $ASGLOGICALID --region {RegionName}

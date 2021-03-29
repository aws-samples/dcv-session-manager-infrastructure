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

#Retrieve the EnginFrame download URL
ef_download_url=$(curl https://download.enginframe.com 2>/dev/null | grep enginframe | grep jar | awk -F'"' '{{ print $2 }}')

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

echo "#EF_GRID_MANAGERS=\"lsf,neutro\"" > /opt/nice/enginframe/conf/plugins/grid/grid.conf 

#Retrieve the Session manager broker download URL
dcvsmb_download_url=$(curl https://download.nice-dcv.com/ 2>/dev/null | grep SessionManagerBrokers | grep el7 | sed -e 's/<[^>]*>//g' | awk -F'"' '{{ print $2 }}')

wget "$dcvsmb_download_url"

dcvsmb_rpm=$(ls *.rpm)

#Install DCVSM broker
yum install -y "$dcvsmb_rpm"

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

#Create the EnginFrame hook required to add the ALB rules entries for the DCV sessions. Compressed with the following command: cat file | gzip | base64 -w0
compressed_starting_hook_file='H4sIAHyTVGAAA51YbXPaRhD+zq/YKDSAG2HAL2nSKjG2FZsZvw3ITqe2Rzmkw9aMkMjpcJzU+e/dPUnoMAI8NR+M9vb29nn27cTrV5vDINocsuS+0j3Zdy8u9096B+7h2cA9657a1h4J86e9VOW871jb21sV/jiJhYTul4F7aH/uXp44bt8+6p2fWXt9fhfE0Rkb872K6we83oB/K4B/3LuPwbD7/fP+B6juGanwMZDQrvyquPc8nMx0XW/sW9U6+sYjtARGtWU0NCtVUjA0wWXC7vgHXQKglODG+CvhSYI+mYH/8cYgAQuH5n2cSO2R8GSPkok7LnWFTLKo850PzakIzQmT97hSfr4cT7Z2dt9vtzqt1k5nZ3frXaf9blfZoZN5dBdEI4EwzcfHxyafotVEmu0mD4dNNmY/44h9T5pePMYtSD5ua7ea9Gm3UPJHKtr0vQcz4eKBizY58qsyZkGkCFVOBSO4vobqazBDCbtwewt/grznkVpUlFMAZk8qLi31OArUvzD2WAimCW5GpxtgiNrP1hCQS8RZ1U7JChFoVbeeraRcZtvqir3qLjyBN5VgetAxG+UbUms75YsYGRcj41JkrOquUroG8yflTgHAgFt48wYoT8E4DVAc3UEQTfDkQaoEPR8mjKIjuWgac3ZysCusYNXAMaqstEFA1ti4oHJbZkMjcIUZR2mt9kZjdr2ll/ikh2G9xS98CJcihAvUXrBcmjDuKAhRBfOGsltfAcuCjZvmBqU6npr3jTmunp7K5M0N7DXqSKw7oLKAj5s+f9iMpmFIe1IE2PzgIAwgSCCKJQJJJAtD7qO7JanPRIROkkEs64cO+DzxRDDkZhgz3xyykEUeFwnqf5ty8QOME5Tv5+LrT4CdmJoqwaoVqVe7beqKXREZaCKeSmJV8kfZyKMS5dnGSOe2wHEZsWHIQcZAIaBkC3weyWAUcAGjWFCbUOJ6cWxjEeTDxFMd4UUY5wQmepTMeXcz60NL6LhtXk28nr8Sa+rQEqg+JpYn4eriAOLRCxGqCOP5GkxPA5kvE740KxEUhcyaiOCBSW76UWLSOHt7xcIpT6xqSSaXgu9z6uxMYj8i7L38JEwLxUOWFCniWqGwhiEN0IqMyI1RJ8zT4S544BFcpLgoNUGN6RQC0bgIrIEVovYS5/Xc2RKawyCRPOJiRclkGqWZtCaRaif5ZiRPdTDk7mutaMS1r1hSmQ6WU20VgbqrcwzmBhRh6qpUL05ogB/ztGngmE1kTsz6DMxYvRPxdOIS48gPJlckR2D8lhjPZ9sTSEETtMbMn13zn5b5HtFkUh9qZm3JYE3tL6U/u/sorf8TAiPt9kdqP0ZBe9Q63AJWzGtNc1mno3vO/AiaocEIZXee4tKzErEnOJWtjhePzC6kiw6SPxMRy9iLQzh2nIsBCSj4zyeraY6Z9O4xP4xjKScHsc+t7dY2LWBZ4D1V71/rCGy9iBc9bUuIKSv+FH4+m5V1rbQL3EsqG7O3UjBdsCrwBQGrQ2S8UgbpDOcJtOikOdth9LADz7evYkJrcKufwOTfoFWOL3ek6HD1OaMzXCsZQNdmlTpfTd5UCBykLlZoLAL5o7yaxDRUIyPvJTn++d5SkgRj9ljv02ZqZNkR8Aprx+cjNg3papCLmzJ2o+l4yEV9r9FYmx/PHc/zYwFQqwy2Bre+sOX3dqNRsievDrqsl18eN4ySbcTdsqqltbW0UsFmzOFagVen24sjP1CjFz4HPPQtcofe+DB1onyUaxWubrqmybx0j/Njwi0cA9+Z8N/OF6q1mEql018FGcucvrykvnNaVtc1WZsN9NnAqs9T1Hi7PvuBRT6kUiD0mhI9NrL7e/YemYScT6CdpU72Q0LvzLH73QOnd2W7A3sw6J2fuU63f2Q77vH5wLH0l60X7lO/VegvWC/c98Xev+yfXHSd4yWZSO/WasoY1TIzffv03LENsMDAV/JOMi7GDjlAb+VLdh7aJ/ZR17Gz594hDfSSX2ZmYkRoLLFl/20fXDr0jfhbpnV4cNUZnGrKq0xmygU/RgVD+h9paSe+RhIAAA=='
echo "$compressed_starting_hook_file" | base64 -d | gunzip > $NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/interactive/bin/alb.session.starting.hook.sh
sed -i "s/@ALB_DNS_NAME@/{ALB_DNS_NAME}/" $NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/interactive/bin/alb.session.starting.hook.sh
sed -i "s/@RegionName@/{RegionName}/" $NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/interactive/bin/alb.session.starting.hook.sh

#Create the EnginFrame hook required to remove the ALB rules entries for the DCV sessions. Compressed with the following command: cat file | gzip | base64 -w0
compressed_closing_hook_file='H4sIAKaTVGAAA51XbVPiSBD+zq/oy3ILWJcIqOzt3mVXxJxShUrxolenVDYkA6QqJGwysJzn/vfrniQkSAjW6gednp6efp5+pmfy7pfjse0ej41gVmh2LvTu8KLTbumXt339tnmjqedkjEfnoctdb6Cenp4U2Hrh+RyaD339UvurOewM9J521b67Vc97bGp77q0xZ+cF3bJZuQL/FQB/mDnzQNJ6vbveJyieS6FxbXOoFX4U9BlzFhtf3ZxbarGMuTEXI4FUrEqVVJQiOUgpwzAwpuxT2gIgnOBJ+jNgQYA5ybb1+Ukig+GM5ZkX8NSQ8ERDbvhTxtMOkWXX5zsby0vfkRcGn+FM9v58vjg5a3w8rdar1bP6WePkQ732oSHi0M7MndruxEeY8nq9VtgSowZcrinMGSvG3Hj2XON7oJjeHJcg+bisVlXot1ZFy++h6dgyV3LA/BXza5TIj8LcsF1BqEjKnsDjIxTfgexwaMBoBH8AnzFXTArKqQCbkahLVQwntvjjeKbhgCyDHtGp21ii2qs5BKQTcWqxnjFDBKrFk1czIZfRsrJgr9iAFzCXHGQT6nIle0EY7Sx7EiujY2V0qoxabAinR5CfSTsJAAlG8P49kE5BurHR7E7Bdhe4cz90grYFC4Oqw5mvSFtxYrA5UfDUwDW65MYgIAdidOm47YuRIjAnzEB45WeTYvZwpLfklC7D4YgPbAxD34Eueu9EzhSMPrEddEHdkLrTM6CqcPSkHJHUcde4b2xx9fKSZVeOsNeILfHcAR0L+HxssdWxu3QcWhMiwOYHLccGOwDX4wgk4IbjMAvTzZC+4buYJAXEY72qg8UC07fHTHY8w5LHhmO4JvMD9P+2ZP6/IHXQfhGbH78AdmJqqgSrlEivNFLSjk3flTCEt+TEKmdrXomr4sZqM8hnlOAYusbYYcA9oBKQ2GyLudye2MyHiedTmxDmcrJtZRfkamGKjvAmjFsGGTMKtrJ72vShPXSMlPuF2bZysYYJ7YFqobBMDvfdFniTNyIUFcb9UzDNFMh4mvCFqkRQVDJ14dsrgzPZcgOZrrPf7g1nyQK1mKHkTPA9Rp3d4NiPCHs73gllIXiIRBEiLiUOBxhKAcpRRByMOmEsh6m9Yi50Q1wkTRDXdAiBaNwFVsETItYS5+U42QyaHTvgzGV+zpGJPDKVdEBIpU68GMkTHQy5+1pKGnHpKx6pyAePUymPwHSqWwzGAQRh4qlUTnaogOWxsGngNRvwmJjDCoxYnfrecqET48gPisvlE5B+DaTXd9sLcJ9u0JIhPzflf6ryR0QTWS0oyaU9F2sYfy/90dtHeP1MCaSw21+J9ViF1DDV4Xawoq5Tnoc63WsoOQKPLh8RNqXdZOfKTiH8pcP2E0SzgphIBTEn23LJOue0EBlpmuFR3+IGEWdRg7FKo5FCSw9xEmedwwWFEaLNJQVjbI7zRurlbYAb+aYJcrDtCnowTfoTM5Nklty0UerFLyCzb1Dd18cpZJKEyL+cBNyfRVrFmE16GGe1q6Gfy+4glwq91+mFjru2bwdar9katO81va/1+/hRhd9WN3cDTQIVJHzm14M5VjD1fKeX/p6Vl1pHu2oOtGjcvqQmkfG1tzHjF560J5b2t9YaDui/67v+Xq/L1n29f5NyzgsZOT9oF8Nep9scXEsF/Nz4H76tg3qaDgAA'
echo "$compressed_closing_hook_file" | base64 -d | gunzip > $NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/interactive/bin/alb.session.closing.hook.sh
sed -i "s/@ALB_DNS_NAME@/{ALB_DNS_NAME}/" $NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/interactive/bin/alb.session.closing.hook.sh
sed -i "s/@RegionName@/{RegionName}/" $NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/interactive/bin/alb.session.closing.hook.sh


chmod +x $NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/interactive/bin/alb.session.closing.hook.sh
chmod +x $NICE_ROOT/enginframe/$EF_VERSION/enginframe/plugins/interactive/bin/alb.session.starting.hook.sh

#Publish the linux service in EnginFrame
#Configure the linux service in EnginFrame
sed -i 's/<ef:metadata attribute="VDI_REMOTE">.*$/<ef:metadata attribute="VDI_REMOTE">dcv2sm<\/ef:metadata>\n<ef:metadata attribute="VDI_CLUSTER">dcvsm_cluster1:dcvsm<\/ef:metadata>/' \
        $NICE_ROOT/enginframe/data/plugins/vdi/services/catalog/interactive_builtin_linux_desktop/WEBAPP/service.xml
#Compressed with the following command: cat file | gzip | base64 -w0
compressed_linux_service='H4sIAGaUU2AAA61WbY+bRhD+fr8Cre5bhQEnaVJ0JsIG36FgYwG2lFYVWsP6vOnCInbx3f37zoLt+pJWV9NafPAOM88zb8zs3efnkmkH0gjKqwmyRibSSJXzglaPE7RO5/on9Nm5Iztb1Jwz0migXwmb7CZoL2VtG8bT09OIVI+02jW4JKOcl8bYNE3DV7K5kiFNkAY4JujWn2fJKopCP868IEaalGyCdAs5Nxr8FA+ua/ai45xpdUN5Q+XLBGHG+JNCYSSXx6Mu+W+Hgtpw0FvAF78fQU5AipPmRMsZFmKCBBEqRp3htsr3EAijVfusfy9G2p4WBYFc7DAT4DotJohWkjQ4l/RAsm1LmaRV1plnBRF/SF6P6nbLqNiT4jsnICv8jCib9ggoyuzoXvZNXJh0ZiJvaC01+VITsCHP0viGD7iXIufO6P9d8BhHomupc/Ejt3xhRCtJQTGo5g0hFbr0pDMBF5Tamx5UUHsnVHnSvD5PnWInfqVYEokLLLGGpWzotpVAlyyyxI83wczPlu7CR38DdDK7CmwTJME0CIP0K3JUVoYj+Yup73nuNATnumYZDhV4yHmzyYbDp19X/iuC4VDuOn2IYuQs4TAcJXSTNFtEXjAPfC+bQinIDhclrYZDzmLfTYNomaWB6paxab3XLVMff0qt9/aHj/D8ZFq2af5fTp9oxpZuvtMtoPnZhufDu1+vZAiWqR+7szTYQBDAkSCnK/uVMBsvyKL/YBv7iyiFiIr8MBblAIBZuE4gkg4BhkzOWgH9ZtndcQCe5ydf0miVLdyle69w1ZQvoE9aJq8vIiyejR8n0CBd0cyRqTfWLx+Hd8Ma/mT3cbReQdLPS+gf8P4l5mo9DYPkAbprHoWeivk4qt/CVV81r/r53m5LKpHG8JbAbg27vaYl/ZoDMceFnvNq1y9jz03dLI6i1KhZC/taGLBTjROrkQMb44/Gm7PJUJAnuxHZqSPSeCvrVuolLyDOijclZkhriIAKHvcJ3CYuVtDKTR96v35waUsr+1a9R2dt8lzzRnZGZxm6hXTOIKgwus8uvizj9tW0VXBGnzS9X6cjsT8hd7nuXx6vJcZf14kLyfmm4tz0Gv0Nybn5E+zaUFRVCQAA'
echo "$compressed_linux_service" | base64 -d | gunzip > $NICE_ROOT/enginframe/data/plugins/vdi/services/published/interactive_builtin_linux_desktop.xml

#Configure the windows service EnginFrame
sed -i 's/<ef:metadata attribute="VDI_REMOTE">.*$/<ef:metadata attribute="VDI_REMOTE">dcv2sm<\/ef:metadata>\n<ef:metadata attribute="VDI_CLUSTER">dcvsm_cluster1:dcvsm<\/ef:metadata>/' \
        $NICE_ROOT/enginframe/data/plugins/vdi/services/catalog/interactive_builtin_windows_desktop/WEBAPP/service.xml
#Compressed with the following command: cat file | gzip | base64 -w0
compressed_windows_service='H4sIAAiVU2AAA62WbW+jOBDH3/dTIKvvTgTI7eqqqGFFAtkikRIByao6nSwCTuM9gxE2Sfvtdwwkl95WuobbKC/w2POb//hpfP/lpWDagdSC8nKKrJGJNFJmPKfl8xStk4V+h77Y92Q3ERXnjNQajC/FhOymaC9lNTGM4/E4IuUzLXd1WpBRxgtjbJqm4SnbQtmQJkgNMabo1lvgeBWGgRdh14+QJiWbIt1C9o0GPxUnrSr2qqcZ06qa8prK1ylKGeNHRWEkk31Tl/zPQ04n0NAb4Iu/esgJpGLSjGgZS4WYIkGEylFnaVNme0jkSMucH4X+7w6k7WmeE5iNXcoEiKf5FNFSkjrNJD0QvG0ok7TEPQDnRPwteTWqmi2jYk9yNGiSTuqV9hIM9reOr7kd/944dVwMBCA/65V108sVBe7Tx9/Fxbyc50dkNa2kJl8rAn7kRRrf00PaWZF9b3Rfbx1bASrgdQIy8b4C+crIpYB2HERW9g8ELohM81SmWiplTbeNBI7/mHiRM0/8jYfngRPHyO4XqUWcXK7G4MCZeQE6rchVsI3r43CgEOUbecsw8ZCdZ4exKK52nwfrGLJp/WFRMtYI2MnWpG1eRYuXOPaijT/38KOz9NC7+3MAbOPH/swP/OQJ2WoDDeV4y5nnus4sAGntyR0K8l1kf+C8D8UnTyvvTYChIGedPISwso/QGMqA3Z3gZej6C99z8ezp/9HmkeckfviIE19tkLFpfdItUx/fJdanyec/4P+baU1M89eo/cVBoDRtvCgG+S3088ga/X43HltDxa7hA3+NwvUKTv+5Sr1L+zBztZ4FfvwAyS/CwFXHur9l/4urdhovu6u52RZUIo2lWwLFN2jLnhZ3VRDMPM31jJe7rlq7TuLgKAwTo2IN1CphQNE1TlGNDKIx/mx84LwYCnryHJGdaiKNN7JqpF7wHDIteV2kDGk1EQ2TfV2AWnpRP1ZO8tAp+0nUlpaTW9WPzqPJS8Vr2TqdbegWJnQOaQXhV3xx1Ru3b+4AhTO6adO7ajgS+xO5ne2us3+5GP+8OC4s58eMfdON6B5R9s0Py80JFngJAAA='
echo "$compressed_windows_service" | base64 -d | gunzip > $NICE_ROOT/enginframe/data/plugins/vdi/services/published/interactive_builtin_windows_desktop.xml

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
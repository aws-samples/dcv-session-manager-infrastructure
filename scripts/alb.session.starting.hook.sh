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

ALB_PUBLIC_DNS_NAME=@ALB_DNS_NAME@
ALB_PORT=443
export AWS_DEFAULT_REGION=@RegionName@
_die() {
    echo "ERROR: $@"
    exit 1
}
_help() {
    _cmd=$(basename "$0")
    echo "$_cmd"
    echo "Usage:"
    echo "  $_cmd \"<session-id>\" \"<alb-host>\" \"<alb-port>\" \"<target-host>\" \"<target-port>\" \"<target-web-url-path>\""
    echo "  $_cmd \"tmp3569402005256372176\" \"alb-enginframe-xxx.eu-west-1.elb.amazonaws.com\" 443 \"10.0.0.10\" 8443 \"/dcv-server1\""
}
main() {

    if [[ $# -lt 6 ]] ; then
        _help
        exit 0
    fi
    local -- _session_id=$1
    local -- _alb_host=$2
    local -- _alb_port=$3
    local -- _target_host=$(echo $6 | cut -c 2-)
    local -- _target_port=$5
    local -- _target_web_url_path=$6
    [ -z "$_session_id" ] && _die "Missing input Session Id parameter."
    [ -z "$_alb_host" ] && _die "Missing input ALB Host parameter."
    [ -z "$_alb_port" ] && _die "Missing input ALB Port parameter."
    [ -z "$_target_host" ] && _die "Missing input Target Host parameter."
    [ -z "$_target_port" ] && _die "Missing input Target Port parameter."
    [ -z "$_target_web_url_path" ] && _die "Missing input Target Web Url Path parameter."
    local -- _target_host_filter=$([[ $_target_host == *\.* ]] && echo "$_target_host" || echo "$_target_host.*")

    aws help >/dev/null || _die "AWS Cli is not installed."

    local -- _alb_arn=$(aws elbv2 describe-load-balancers --query "LoadBalancers[? DNSName == '$_alb_host'].LoadBalancerArn" --output text)
    [ -n "$_alb_arn" ] || _die "Unable to get ALB identifier for the ALB ($_alb_host)."

    local -- _vpc_id=$(aws elbv2 describe-load-balancers --load-balancer-arns "$_alb_arn" \
        --query "LoadBalancers[].VpcId" --output text)
    [ -n "$_vpc_id" ] || _die "Unable to detect VPC of the ALB ($_alb_host)."

    local -- _instance_id=$(aws ec2 describe-instances --filters "Name=private-dns-name,Values=$_target_host_filter" \
        --query "Reservations[].Instances[? VpcId == '$_vpc_id'].InstanceId" --output text)
    [ -n "$_instance_id" ] || _die "Unable to get Instance Id for the given Private DNS name filter ($_target_host_filter) in the VPC ($_vpc_id)."

    local -- _listener_arn=$(aws elbv2 describe-listeners --load-balancer-arn "$_alb_arn" \
        --query 'Listeners[? Port == `'$_alb_port'`].ListenerArn' --output text)
    [ -n "$_listener_arn" ] || _die "Listener for port ($_alb_port) does not exist in the ALB ($_alb_host)."

    local -- _target_group_name=$(printf "%s" "$_session_id" | tr -c 'a-zA-Z0-9' - | tr -d '-')
    local -- _target_group_arn=$(aws elbv2 describe-target-groups --load-balancer-arn "$_alb_arn" \
        --query "TargetGroups[? TargetGroupName == '$_target_group_name'].TargetGroupArn" --output text)
    if [ -z "$_target_group_arn" ]; then

        _target_group_arn=$(aws elbv2 create-target-group --name "$_target_group_name" --protocol HTTPS --port "$_target_port" --matcher "HttpCode=404" --vpc-id "$_vpc_id" \
        --query "TargetGroups[0].TargetGroupArn" --output text)
        [ -n "$_target_group_arn" ] || _die "Unable to create Target Group ($_target_group_name) in the VPC ($_vpc_id)"




        aws elbv2 register-targets --target-group-arn "$_target_group_arn" --targets "Id=$_instance_id" >/dev/null
        [ $? -eq 0 ] || _die "Unable to register Instance ($_instance_id) in the Target Group ($_target_group_arn)."

        local -- _current_priority=$(aws elbv2 describe-rules --listener-arn "$_listener_arn" \
        --query "max(Rules[? Priority != 'default'].Priority.to_number(@))" --output text)
        [ -n "$_current_priority" ] || _current_priority=0

        local -- _priority=$((_current_priority+1))
        local -- _target_path="$_target_web_url_path*"
        local -- _rule_arn=$(aws elbv2 create-rule --listener-arn "$_listener_arn" --priority "$_priority" \
        --conditions Field=path-pattern,Values="$_target_path" --actions Type=forward,TargetGroupArn=$_target_group_arn \
        --query "Rules[0].RuleArn" --output text)
        [ -n "$_rule_arn" ] || _die "Unable to create Rule for the Listener ($_listener_arn), Target Group ($_target_group_arn) and target path ($_target_path)."
    fi
    sleep 10

    export INTERACTIVE_SESSION_TARGET_HOST="$_alb_host"
    export INTERACTIVE_SESSION_TARGET_PORT="$_alb_port"
    export INTERACTIVE_SESSION_TARGET_WEBURLPATH="$_target_web_url_path"
}
if [ "$INTERACTIVE_SESSION_REMOTE" = "dcv2sm" ]; then
    main "$INTERACTIVE_SESSION_DELEGATESESSIONID" "$ALB_PUBLIC_DNS_NAME" "$ALB_PORT" "$INTERACTIVE_SESSION_EXECUTION_HOST" "$INTERACTIVE_SESSION_DCV2SM_EXECUTION_PORT" "$INTERACTIVE_SESSION_DCV2SM_WEBURLPATH"
fi
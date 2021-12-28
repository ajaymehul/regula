package rules.tf_aws_tagging
__rego__metadoc__ := {
  "id": "FG_R00200",
  "title": "Resource should contain tags adhering to tagging policy",
  "description": "Resource should contain mandatory tags specified in tagging policy",
  "custom": {
    "severity": "Low"
  }
}

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

taggable_resource_types = {
  "aws_accessanalyzer_analyzer",
  "aws_acm_certificate",
  "aws_acmpca_certificate_authority",
  "aws_ami",
  "aws_api_gateway_client_certificate",
  "aws_api_gateway_domain_name",
  "aws_api_gateway_rest_api",
  "aws_api_gateway_stage",
  "aws_api_gateway_usage_plan",
  "aws_api_gateway_vpc_link",
  "aws_apigatewayv2_api",
  "aws_apigatewayv2_domain_name",
  "aws_apigatewayv2_stage",
  "aws_apigatewayv2_vpc_link",
  "aws_athena_workgroup",
  "aws_autoscaling_group",
  "aws_cloudformation_stack",
  "aws_cloudformation_stack_set",
  "aws_cloudfront_distribution",
  "aws_cloudtrail",
  "aws_cloudwatch_event_rule",
  "aws_cloudwatch_log_group",
  "aws_cloudwatch_metric_alarm",
  "aws_cognito_user_pool",
  "aws_config_aggregate_authorization",
  "aws_config_config_rule",
  "aws_config_configuration_aggregator",
  "aws_customer_gateway",
  "aws_db_event_subscription",
  "aws_db_instance",
  "aws_db_option_group",
  "aws_db_parameter_group",
  "aws_db_snapshot",
  "aws_db_subnet_group",
  "aws_directory_service_directory",
  "aws_docdb_cluster",
  "aws_docdb_cluster_instance",
  "aws_dynamodb_table",
  "aws_ebs_snapshot",
  "aws_ebs_volume",
  "aws_ecr_repository",
  "aws_ecs_cluster",
  "aws_ecs_service",
  "aws_ecs_task_definition",
  "aws_efs_file_system",
  "aws_egress_only_internet_gateway",
  "aws_eip",
  "aws_eks_cluster",
  "aws_elasticache_cluster",
  "aws_elasticache_replication_group",
  "aws_elasticsearch_domain",
  "aws_elb",
  "aws_flow_log",
  "aws_glacier_vault",
  "aws_glue_crawler",
  "aws_glue_job",
  "aws_glue_trigger",
  "aws_guardduty_detector",
  "aws_iam_role",
  "aws_iam_user",
  "aws_inspector_assessment_template",
  "aws_instance",
  "aws_internet_gateway",
  "aws_key_pair",
  "aws_kinesis_firehose_delivery_stream",
  "aws_kinesis_stream",
  "aws_kms_key",
  "aws_lambda_function",
  "aws_launch_template",
  "aws_lb",
  "aws_lb_target_group",
  "aws_media_store_container",
  "aws_nat_gateway",
  "aws_neptune_cluster",
  "aws_neptune_cluster_instance",
  "aws_network_acl",
  "aws_network_interface",
  "aws_placement_group",
  "aws_ram_resource_share",
  "aws_rds_cluster",
  "aws_rds_cluster_instance",
  "aws_rds_cluster_parameter_group",
  "aws_redshift_cluster",
  "aws_redshift_parameter_group",
  "aws_redshift_subnet_group",
  "aws_route53_health_check",
  "aws_route53_zone",
  "aws_route_table",
  "aws_s3_bucket",
  "aws_sagemaker_endpoint",
  "aws_sagemaker_endpoint_configuration",
  "aws_sagemaker_model",
  "aws_sagemaker_notebook_instance",
  "aws_secretsmanager_secret",
  "aws_security_group",
  "aws_sfn_state_machine",
  "aws_sns_topic",
  "aws_spot_fleet_request",
  "aws_sqs_queue",
  "aws_ssm_activation",
  "aws_ssm_document",
  "aws_ssm_maintenance_window",
  "aws_ssm_parameter",
  "aws_ssm_patch_baseline",
  "aws_subnet",
  "aws_vpc",
  "aws_vpc_dhcp_options",
  "aws_vpc_endpoint",
  "aws_vpc_endpoint_service",
  "aws_vpc_peering_connection",
  "aws_vpn_connection",
  "aws_vpn_gateway",
  "aws_waf_rate_based_rule",
  "aws_waf_rule",
  "aws_waf_rule_group",
  "aws_waf_web_acl",
  "aws_wafregional_rate_based_rule",
  "aws_wafregional_rule",
  "aws_wafregional_rule_group",
  "aws_wafregional_web_acl",
  "aws_wafv2_regex_pattern_set",
  "aws_wafv2_rule_group",
  "aws_wafv2_web_acl",
  "aws_workspaces_directory",
  "aws_workspaces_ip_group",
  "aws_workspaces_workspace"
}

scanned_resource_types := fugue.resource_types

# For each taggable resource type, add each of its resources 
# to the taggable_resources collection
taggable_resources[id] = resource {
  some type_name
  scanned_resource_types[type_name]
  taggable_resource_types[type_name]
  resources = fugue.resources(type_name)
  resource = resources[id]
}

# List of mandatory tags
mandatory_tags = {
    "ApplicationName",
    "CostCenter",
    "Environment",
    "ApplicationOwner"
}

# Set difference to check if all the mandatory_tags are in input_tags
contains_all_tags (resource) {
    # Set Comprehension for getting names of tags in resource
    input_tags := {tagname | resource.tags[i] ; tagname := i}
    count(mandatory_tags - input_tags) <= 0
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
policy[p] {
    resource = taggable_resources[_]
    contains_all_tags(resource)
    p = fugue.allow_resource(resource)
} {
    resource = taggable_resources[_]
    not contains_all_tags(resource)
    p = fugue.deny_resource(resource)
}

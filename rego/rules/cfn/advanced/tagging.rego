package rules.cfn_aws_tagging
__rego__metadoc__ := {
  "id": "FG_R00201",
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

input_type := "cfn"

taggable_resource_types = {
    "AWS::EC2::EIP",
    "AWS::EC2::Image",
    "AWS::EC2::Instance",
    "AWS::EC2::NetworkInterface",
    "AWS::EC2::SecurityGroup",
    "AWS::EC2::Snapshot",
    "AWS::EC2::Volume",
    "AWS::EFS::FileSystem",
    "AWS::ECS::TaskDefinition",
    "AWS::ECS::Cluster",
    "AWS::ECS::Service",
    "AWS::ElastiCache::CacheCluster",
    "AWS::ElasticLoadBalancing::LoadBalancer",
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "AWS::ElasticLoadBalancingV2::TargetGroup",
    "AWS::RDS::DBClusterParameterGroup",
    "AWS::RDS::EventSubscription",
    "AWS::RDS::OptionGroup",
    "AWS::RDS::DBParameterGroup",
    "AWS::RDS::ReservedDBInstance",
    "AWS::RDS::DBSecurityGroup",
    "AWS::RDS::DBSubnetGroup",
    "AWS::S3::Bucket"
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

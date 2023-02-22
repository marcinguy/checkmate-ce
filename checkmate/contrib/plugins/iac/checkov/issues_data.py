# -*- coding: utf-8 -*-


issues_data = {

    "CKV_DOCKER_4": {
        "title": "Ensure that COPY is used instead of ADD in Dockerfiles",
        "display_name": "Ensure that COPY is used instead of ADD in Dockerfiles",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "Ensure that COPY is used instead of ADD in Dockerfiles"

    },
    "CKV_DOCKER_11": {
        "title": "Ensure From Alias are unique for multistage builds.",
        "display_name": "Ensure From Alias are unique for multistage builds.",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "Ensure From Alias are unique for multistage builds."
    },
    "CKV_DOCKER_1": {
        "title": "Ensure port 22 is not exposed",
        "display_name": "Ensure port 22 is not exposed",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "Ensure port 22 is not exposed"
    },
    "CKV_DOCKER_2": {
        "title": "Ensure that HEALTHCHECK instructions have been added to container images",
        "display_name": "Ensure that HEALTHCHECK instructions have been added to container images",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "Ensure that HEALTHCHECK instructions have been added to container images"
    },
    "CKV_DOCKER_6": {
        "title": "Ensure that LABEL maintainer is used instead of MAINTAINER (deprecated)",
        "display_name": "Ensure that LABEL maintainer is used instead of MAINTAINER (deprecated)",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "Ensure that LABEL maintainer is used instead of MAINTAINER (deprecated)"
    },
    "CKV_DOCKER_7": {
        "title": "Ensure the base image uses a non latest version tag",
        "display_name": "Ensure the base image uses a non latest version tag",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "Ensure the base image uses a non latest version tag"
    },
    "CKV_DOCKER_8": {
        "title": "Ensure the last USER is not root",
        "display_name": "Ensure the last USER is not root",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "Ensure the last USER is not root"
    },
    "CKV_DOCKER_9": {
        "title": "Ensure that APT isn't used",
        "display_name": "Ensure that APT isn't used",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "Ensure that APT isn't used"
    },
    "CKV_DOCKER_5": {
        "title": "Ensure update instructions are not use alone in the Dockerfile",
        "display_name": "Ensure update instructions are not use alone in the Dockerfile",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "Ensure update instructions are not use alone in the Dockerfile"
    },
    "CKV_DOCKER_3": {
        "title": "Ensure that a user for the container has been created",
        "display_name": "Ensure that a user for the container has been created",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "Ensure that a user for the container has been created"
    },
    "CKV_DOCKER_10": {
        "title": "Ensure that WORKDIR values are absolute paths",
        "display_name": "Ensure that WORKDIR values are absolute paths",
        "severity": "3",
        "categories": [
            "security"
        ],
        "description": "Ensure that WORKDIR values are absolute paths"
    },
  "CKV_ALI_1": {
    "display_name": "CKV_ALI_1",
    "severity": "1",
    "description": "Alibaba Cloud OSS bucket accessible to public",
    "categories": [
      "security"
    ],
    "title": "Alibaba Cloud OSS bucket accessible to public"
  },
  "CKV_ALI_6": {
    "display_name": "CKV_ALI_6",
    "severity": "1",
    "description": "Ensure OSS bucket is encrypted with Customer Master Key",
    "categories": [
      "security"
    ],
    "title": "Ensure OSS bucket is encrypted with Customer Master Key"
  },
  "CKV_ALI_12": {
    "display_name": "CKV_ALI_12",
    "severity": "1",
    "description": "Ensure the OSS bucket has access logging enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure the OSS bucket has access logging enabled"
  },
  "CKV_ALI_11": {
    "display_name": "CKV_ALI_11",
    "severity": "1",
    "description": "Ensure OSS bucket has transfer Acceleration enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure OSS bucket has transfer Acceleration enabled"
  },
  "CKV_ALI_10": {
    "display_name": "CKV_ALI_10",
    "severity": "1",
    "description": "Ensure OSS bucket has versioning enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure OSS bucket has versioning enabled"
  },
  "CKV_ALI_25": {
    "display_name": "CKV_ALI_25",
    "severity": "1",
    "description": "Ensure RDS Instance SQL Collector Retention Period should be greater than 180",
    "categories": [
      "security"
    ],
    "title": "Ensure RDS Instance SQL Collector Retention Period should be greater than 180"
  },
  "CKV_ALI_20": {
    "display_name": "CKV_ALI_20",
    "severity": "1",
    "description": "Ensure RDS instance uses SSL",
    "categories": [
      "security"
    ],
    "title": "Ensure RDS instance uses SSL"
  },
  "CKV_ALI_9": {
    "display_name": "CKV_ALI_9",
    "severity": "1",
    "description": "Ensure database instance is not public",
    "categories": [
      "security"
    ],
    "title": "Ensure database instance is not public"
  },
  "CKV_ALI_5": {
    "display_name": "CKV_ALI_5",
    "severity": "1",
    "description": "Ensure Action Trail Logging for all events",
    "categories": [
      "security"
    ],
    "title": "Ensure Action Trail Logging for all events"
  },
  "CKV_ALI_4": {
    "display_name": "CKV_ALI_4",
    "severity": "1",
    "description": "Ensure Action Trail Logging for all regions",
    "categories": [
      "security"
    ],
    "title": "Ensure Action Trail Logging for all regions"
  },
  "CKV_AWS_161": {
    "display_name": "CKV_AWS_161",
    "severity": "1",
    "description": "Ensure RDS database has IAM authentication enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure RDS database has IAM authentication enabled"
  },
  "CKV_AWS_17": {
    "display_name": "CKV_AWS_17",
    "severity": "1",
    "description": "Ensure all data stored in RDS is not publicly accessible",
    "categories": [
      "security"
    ],
    "title": "Ensure all data stored in RDS is not publicly accessible"
  },
  "CKV_AWS_226": {
    "display_name": "CKV_AWS_226",
    "severity": "1",
    "description": "Ensure DB instance gets all minor upgrades automatically",
    "categories": [
      "security"
    ],
    "title": "Ensure DB instance gets all minor upgrades automatically"
  },
  "CKV_AWS_118": {
    "display_name": "CKV_AWS_118",
    "severity": "1",
    "description": "Ensure that enhanced monitoring is enabled for Amazon RDS instances",
    "categories": [
      "security"
    ],
    "title": "Ensure that enhanced monitoring is enabled for Amazon RDS instances"
  },
  "CKV_AWS_129": {
    "display_name": "CKV_AWS_129",
    "severity": "1",
    "description": "Ensure that respective logs of Amazon Relational Database Service (Amazon RDS) are enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure that respective logs of Amazon Relational Database Service (Amazon RDS) are enabled"
  },
  "CKV_AWS_157": {
    "display_name": "CKV_AWS_157",
    "severity": "1",
    "description": "Ensure that RDS instances have Multi-AZ enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure that RDS instances have Multi-AZ enabled"
  },
  "CKV_AWS_133": {
    "display_name": "CKV_AWS_133",
    "severity": "1",
    "description": "Ensure that RDS instances has backup policy",
    "categories": [
      "security"
    ],
    "title": "Ensure that RDS instances has backup policy"
  },
  "CKV_AWS_16": {
    "display_name": "CKV_AWS_16",
    "severity": "1",
    "description": "Ensure all data stored in the RDS is securely encrypted at rest",
    "categories": [
      "security"
    ],
    "title": "Ensure all data stored in the RDS is securely encrypted at rest"
  },
  "CKV_AWS_23": {
    "display_name": "CKV_AWS_23",
    "severity": "1",
    "description": "Ensure every security groups rule has a description",
    "categories": [
      "security"
    ],
    "title": "Ensure every security groups rule has a description"
  },
  "CKV_AWS_79": {
    "display_name": "CKV_AWS_79",
    "severity": "1",
    "description": "Ensure Instance Metadata Service Version 1 is not enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure Instance Metadata Service Version 1 is not enabled"
  },
  "CKV_AWS_126": {
    "display_name": "CKV_AWS_126",
    "severity": "1",
    "description": "Ensure that detailed monitoring is enabled for EC2 instances",
    "categories": [
      "security"
    ],
    "title": "Ensure that detailed monitoring is enabled for EC2 instances"
  },
  "CKV_AWS_8": {
    "display_name": "CKV_AWS_8",
    "severity": "1",
    "description": "Ensure all data stored in the Launch configuration or instance Elastic Blocks Store is securely encrypted",
    "categories": [
      "security"
    ],
    "title": "Ensure all data stored in the Launch configuration or instance Elastic Blocks Store is securely encrypted"
  },
  "CKV_AWS_135": {
    "display_name": "CKV_AWS_135",
    "severity": "1",
    "description": "Ensure that EC2 is EBS optimized",
    "categories": [
      "security"
    ],
    "title": "Ensure that EC2 is EBS optimized"
  },
  "CKV_AWS_46": {
    "display_name": "CKV_AWS_46",
    "severity": "1",
    "description": "Ensure no hard-coded secrets exist in EC2 user data",
    "categories": [
      "security"
    ],
    "title": "Ensure no hard-coded secrets exist in EC2 user data"
  },
  "CKV_AWS_189": {
    "display_name": "CKV_AWS_189",
    "severity": "1",
    "description": "Ensure EBS Volume is encrypted by KMS using a customer managed Key (CMK)",
    "categories": [
      "security"
    ],
    "title": "Ensure EBS Volume is encrypted by KMS using a customer managed Key (CMK)"
  },
  "CKV_AWS_3": {
    "display_name": "CKV_AWS_3",
    "severity": "1",
    "description": "Ensure all data stored in the EBS is securely encrypted",
    "categories": [
      "security"
    ],
    "title": "Ensure all data stored in the EBS is securely encrypted"
  },
  "CKV_AWS_24": {
    "display_name": "CKV_AWS_24",
    "severity": "1",
    "description": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
    "categories": [
      "security"
    ],
    "title": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22"
  },
  "CKV_AWS_130": {
    "display_name": "CKV_AWS_130",
    "severity": "1",
    "description": "Ensure VPC subnets do not assign public IP by default",
    "categories": [
      "security"
    ],
    "title": "Ensure VPC subnets do not assign public IP by default"
  },
  "CKV_AWS_144": {
    "display_name": "CKV_AWS_144",
    "severity": "1",
    "description": "Ensure that S3 bucket has cross-region replication enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure that S3 bucket has cross-region replication enabled"
  },
  "CKV_AWS_136": {
    "display_name": "CKV_AWS_136",
    "severity": "1",
    "description": "Ensure that ECR repositories are encrypted using KMS",
    "categories": [
      "security"
    ],
    "title": "Ensure that ECR repositories are encrypted using KMS"
  },
  "CKV_AWS_51": {
    "display_name": "CKV_AWS_51",
    "severity": "1",
    "description": "Ensure ECR Image Tags are immutable",
    "categories": [
      "security"
    ],
    "title": "Ensure ECR Image Tags are immutable"
  },
  "CKV_AWS_163": {
    "display_name": "CKV_AWS_163",
    "severity": "1",
    "description": "Ensure ECR image scanning on push is enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure ECR image scanning on push is enabled"
  },
  "CKV_AWS_58": {
    "display_name": "CKV_AWS_58",
    "severity": "1",
    "description": "Ensure EKS Cluster has Secrets Encryption Enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure EKS Cluster has Secrets Encryption Enabled"
  },
  "CKV_AWS_37": {
    "display_name": "CKV_AWS_37",
    "severity": "1",
    "description": "Ensure Amazon EKS control plane logging enabled for all log types",
    "categories": [
      "security"
    ],
    "title": "Ensure Amazon EKS control plane logging enabled for all log types"
  },
  "CKV_AWS_39": {
    "display_name": "CKV_AWS_39",
    "severity": "1",
    "description": "Ensure Amazon EKS public endpoint disabled",
    "categories": [
      "security"
    ],
    "title": "Ensure Amazon EKS public endpoint disabled"
  },
  "CKV_AWS_38": {
    "display_name": "CKV_AWS_38",
    "severity": "1",
    "description": "Ensure Amazon EKS public endpoint not accessible to 0.0.0.0/0",
    "categories": [
      "security"
    ],
    "title": "Ensure Amazon EKS public endpoint not accessible to 0.0.0.0/0"
  },
  "CKV_AWS_127": {
    "display_name": "CKV_AWS_127",
    "severity": "1",
    "description": "Ensure that Elastic Load Balancer(s) uses SSL certificates provided by AWS Certificate Manager",
    "categories": [
      "security"
    ],
    "title": "Ensure that Elastic Load Balancer(s) uses SSL certificates provided by AWS Certificate Manager"
  },
  "CKV_AWS_92": {
    "display_name": "CKV_AWS_92",
    "severity": "1",
    "description": "Ensure the ELB has access logging enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure the ELB has access logging enabled"
  },
  "CKV_AWS_84": {
    "display_name": "CKV_AWS_84",
    "severity": "1",
    "description": "Ensure Elasticsearch Domain Logging is enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure Elasticsearch Domain Logging is enabled"
  },
  "CKV_AWS_228": {
    "display_name": "CKV_AWS_228",
    "severity": "1",
    "description": "Verify Elasticsearch domain is using an up to date TLS policy",
    "categories": [
      "security"
    ],
    "title": "Verify Elasticsearch domain is using an up to date TLS policy"
  },
  "CKV_AWS_137": {
    "display_name": "CKV_AWS_137",
    "severity": "1",
    "description": "Ensure that Elasticsearch is configured inside a VPC",
    "categories": [
      "security"
    ],
    "title": "Ensure that Elasticsearch is configured inside a VPC"
  },
  "CKV_AWS_247": {
    "display_name": "CKV_AWS_247",
    "severity": "1",
    "description": "Ensure all data stored in the Elasticsearch is encrypted with a CMK",
    "categories": [
      "security"
    ],
    "title": "Ensure all data stored in the Elasticsearch is encrypted with a CMK"
  },
  "CKV_AWS_248": {
    "display_name": "CKV_AWS_248",
    "severity": "1",
    "description": "Ensure that Elasticsearch is not using the default Security Group",
    "categories": [
      "security"
    ],
    "title": "Ensure that Elasticsearch is not using the default Security Group"
  },
  "CKV_AWS_5": {
    "display_name": "CKV_AWS_5",
    "severity": "1",
    "description": "Ensure all data stored in the Elasticsearch is securely encrypted at rest",
    "categories": [
      "security"
    ],
    "title": "Ensure all data stored in the Elasticsearch is securely encrypted at rest"
  },
  "CKV_AWS_109": {
    "display_name": "CKV_AWS_109",
    "severity": "1",
    "description": "Ensure IAM policies does not allow permissions management / resource exposure without constraints",
    "categories": [
      "security"
    ],
    "title": "Ensure IAM policies does not allow permissions management / resource exposure without constraints"
  },
  "CKV_AWS_111": {
    "display_name": "CKV_AWS_111",
    "severity": "1",
    "description": "Ensure IAM policies does not allow write access without constraints",
    "categories": [
      "security"
    ],
    "title": "Ensure IAM policies does not allow write access without constraints"
  },
  "CKV_AWS_7": {
    "display_name": "CKV_AWS_7",
    "severity": "1",
    "description": "Ensure rotation for customer created CMKs is enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure rotation for customer created CMKs is enabled"
  },
  "CKV_AWS_117": {
    "display_name": "CKV_AWS_117",
    "severity": "1",
    "description": "Ensure that AWS Lambda function is configured inside a VPC",
    "categories": [
      "security"
    ],
    "title": "Ensure that AWS Lambda function is configured inside a VPC"
  },
  "CKV_AWS_116": {
    "display_name": "CKV_AWS_116",
    "severity": "1",
    "description": "Ensure that AWS Lambda function is configured for a Dead Letter Queue(DLQ)",
    "categories": [
      "security"
    ],
    "title": "Ensure that AWS Lambda function is configured for a Dead Letter Queue(DLQ)"
  },
  "CKV_AWS_115": {
    "display_name": "CKV_AWS_115",
    "severity": "1",
    "description": "Ensure that AWS Lambda function is configured for function-level concurrent execution limit",
    "categories": [
      "security"
    ],
    "title": "Ensure that AWS Lambda function is configured for function-level concurrent execution limit"
  },
  "CKV_AWS_50": {
    "display_name": "CKV_AWS_50",
    "severity": "1",
    "description": "X-ray tracing is enabled for Lambda",
    "categories": [
      "security"
    ],
    "title": "X-ray tracing is enabled for Lambda"
  },
  "CKV_AWS_45": {
    "display_name": "CKV_AWS_45",
    "severity": "1",
    "description": "Ensure no hard-coded secrets exist in lambda environment",
    "categories": [
      "security"
    ],
    "title": "Ensure no hard-coded secrets exist in lambda environment"
  },
  "CKV_AWS_173": {
    "display_name": "CKV_AWS_173",
    "severity": "1",
    "description": "Check encryption settings for Lambda environmental variable",
    "categories": [
      "security"
    ],
    "title": "Check encryption settings for Lambda environmental variable"
  },
  "CKV_AWS_101": {
    "display_name": "CKV_AWS_101",
    "severity": "1",
    "description": "Ensure Neptune logging is enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure Neptune logging is enabled"
  },
  "CKV_AWS_44": {
    "display_name": "CKV_AWS_44",
    "severity": "1",
    "description": "Ensure Neptune storage is securely encrypted",
    "categories": [
      "security"
    ],
    "title": "Ensure Neptune storage is securely encrypted"
  },
  "CKV_AWS_41": {
    "display_name": "CKV_AWS_41",
    "severity": "1",
    "description": "Ensure no hard coded AWS access key and secret key exists in provider",
    "categories": [
      "security"
    ],
    "title": "Ensure no hard coded AWS access key and secret key exists in provider"
  },
  "CKV_AWS_139": {
    "display_name": "CKV_AWS_139",
    "severity": "1",
    "description": "Ensure that RDS clusters have deletion protection enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure that RDS clusters have deletion protection enabled"
  },
  "CKV_AWS_96": {
    "display_name": "CKV_AWS_96",
    "severity": "1",
    "description": "Ensure all data stored in Aurora is securely encrypted at rest",
    "categories": [
      "security"
    ],
    "title": "Ensure all data stored in Aurora is securely encrypted at rest"
  },
  "CKV_AWS_128": {
    "display_name": "CKV_AWS_128",
    "severity": "1",
    "description": "Ensure that an Amazon RDS Clusters have AWS Identity and Access Management (IAM) authentication enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure that an Amazon RDS Clusters have AWS Identity and Access Management (IAM) authentication enabled"
  },
  "CKV_AWS_162": {
    "display_name": "CKV_AWS_162",
    "severity": "1",
    "description": "Ensure RDS cluster has IAM authentication enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure RDS cluster has IAM authentication enabled"
  },
  "CKV_AWS_186": {
    "display_name": "CKV_AWS_186",
    "severity": "1",
    "description": "Ensure S3 bucket Object is encrypted by KMS using a customer managed Key (CMK)",
    "categories": [
      "security"
    ],
    "title": "Ensure S3 bucket Object is encrypted by KMS using a customer managed Key (CMK)"
  },
  "CKV_AZURE_141": {
    "display_name": "CKV_AZURE_141",
    "severity": "1",
    "description": "Ensure AKS local admin account is disabled",
    "categories": [
      "security"
    ],
    "title": "Ensure AKS local admin account is disabled"
  },
  "CKV_AZURE_7": {
    "display_name": "CKV_AZURE_7",
    "severity": "1",
    "description": "Ensure AKS cluster has Network Policy configured",
    "categories": [
      "security"
    ],
    "title": "Ensure AKS cluster has Network Policy configured"
  },
  "CKV_AZURE_116": {
    "display_name": "CKV_AZURE_116",
    "severity": "1",
    "description": "Ensure that AKS uses Azure Policies Add-on",
    "categories": [
      "security"
    ],
    "title": "Ensure that AKS uses Azure Policies Add-on"
  },
  "CKV_AZURE_5": {
    "display_name": "CKV_AZURE_5",
    "severity": "1",
    "description": "Ensure RBAC is enabled on AKS clusters",
    "categories": [
      "security"
    ],
    "title": "Ensure RBAC is enabled on AKS clusters"
  },
  "CKV_AZURE_115": {
    "display_name": "CKV_AZURE_115",
    "severity": "1",
    "description": "Ensure that AKS enables private clusters",
    "categories": [
      "security"
    ],
    "title": "Ensure that AKS enables private clusters"
  },
  "CKV_AZURE_8": {
    "display_name": "CKV_AZURE_8",
    "severity": "1",
    "description": "Ensure Kubernetes Dashboard is disabled",
    "categories": [
      "security"
    ],
    "title": "Ensure Kubernetes Dashboard is disabled"
  },
  "CKV_AZURE_117": {
    "display_name": "CKV_AZURE_117",
    "severity": "1",
    "description": "Ensure that AKS uses disk encryption set",
    "categories": [
      "security"
    ],
    "title": "Ensure that AKS uses disk encryption set"
  },
  "CKV_AZURE_6": {
    "display_name": "CKV_AZURE_6",
    "severity": "1",
    "description": "Ensure AKS has an API Server Authorized IP Ranges enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure AKS has an API Server Authorized IP Ranges enabled"
  },
  "CKV_AZURE_4": {
    "display_name": "CKV_AZURE_4",
    "severity": "1",
    "description": "Ensure AKS logging to Azure Monitoring is Configured",
    "categories": [
      "security"
    ],
    "title": "Ensure AKS logging to Azure Monitoring is Configured"
  },
  "CKV_AZURE_63": {
    "display_name": "CKV_AZURE_63",
    "severity": "1",
    "description": "Ensure that App service enables HTTP logging",
    "categories": [
      "security"
    ],
    "title": "Ensure that App service enables HTTP logging"
  },
  "CKV_AZURE_14": {
    "display_name": "CKV_AZURE_14",
    "severity": "1",
    "description": "Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service",
    "categories": [
      "security"
    ],
    "title": "Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service"
  },
  "CKV_AZURE_13": {
    "display_name": "CKV_AZURE_13",
    "severity": "1",
    "description": "Ensure App Service Authentication is set on Azure App Service",
    "categories": [
      "security"
    ],
    "title": "Ensure App Service Authentication is set on Azure App Service"
  },
  "CKV_AZURE_15": {
    "display_name": "CKV_AZURE_15",
    "severity": "1",
    "description": "Ensure web app is using the latest version of TLS encryption",
    "categories": [
      "security"
    ],
    "title": "Ensure web app is using the latest version of TLS encryption"
  },
  "CKV_AZURE_80": {
    "display_name": "CKV_AZURE_80",
    "severity": "1",
    "description": "Ensure that 'Net Framework' version is the latest, if used as a part of the web app",
    "categories": [
      "security"
    ],
    "title": "Ensure that 'Net Framework' version is the latest, if used as a part of the web app"
  },
  "CKV_AZURE_17": {
    "display_name": "CKV_AZURE_17",
    "severity": "1",
    "description": "Ensure the web app has 'Client Certificates (Incoming client certificates)' set",
    "categories": [
      "security"
    ],
    "title": "Ensure the web app has 'Client Certificates (Incoming client certificates)' set"
  },
  "CKV_AZURE_16": {
    "display_name": "CKV_AZURE_16",
    "severity": "1",
    "description": "Ensure that Register with Azure Active Directory is enabled on App Service",
    "categories": [
      "security"
    ],
    "title": "Ensure that Register with Azure Active Directory is enabled on App Service"
  },
  "CKV_AZURE_88": {
    "display_name": "CKV_AZURE_88",
    "severity": "1",
    "description": "Ensure that app services use Azure Files",
    "categories": [
      "security"
    ],
    "title": "Ensure that app services use Azure Files"
  },
  "CKV_AZURE_18": {
    "display_name": "CKV_AZURE_18",
    "severity": "1",
    "description": "Ensure that 'HTTP Version' is the latest if used to run the web app",
    "categories": [
      "security"
    ],
    "title": "Ensure that 'HTTP Version' is the latest if used to run the web app"
  },
  "CKV_AZURE_78": {
    "display_name": "CKV_AZURE_78",
    "severity": "1",
    "description": "Ensure FTP deployments are disabled",
    "categories": [
      "security"
    ],
    "title": "Ensure FTP deployments are disabled"
  },
  "CKV_AZURE_71": {
    "display_name": "CKV_AZURE_71",
    "severity": "1",
    "description": "Ensure that Managed identity provider is enabled for app services",
    "categories": [
      "security"
    ],
    "title": "Ensure that Managed identity provider is enabled for app services"
  },
  "CKV_AZURE_66": {
    "display_name": "CKV_AZURE_66",
    "severity": "1",
    "description": "Ensure that App service enables failed request tracing",
    "categories": [
      "security"
    ],
    "title": "Ensure that App service enables failed request tracing"
  },
  "CKV_AZURE_65": {
    "display_name": "CKV_AZURE_65",
    "severity": "1",
    "description": "Ensure that App service enables detailed error messages",
    "categories": [
      "security"
    ],
    "title": "Ensure that App service enables detailed error messages"
  },
  "CKV_AZURE_149": {
    "display_name": "CKV_AZURE_149",
    "severity": "1",
    "description": "Ensure that Virtual machine does not enable password authentication",
    "categories": [
      "security"
    ],
    "title": "Ensure that Virtual machine does not enable password authentication"
  },
  "CKV_AZURE_50": {
    "display_name": "CKV_AZURE_50",
    "severity": "1",
    "description": "Ensure Virtual Machine Extensions are not Installed",
    "categories": [
      "security"
    ],
    "title": "Ensure Virtual Machine Extensions are not Installed"
  },
  "CKV_AZURE_1": {
    "display_name": "CKV_AZURE_1",
    "severity": "1",
    "description": "Ensure Azure Instance does not use basic authentication(Use SSH Key Instead)",
    "categories": [
      "security"
    ],
    "title": "Ensure Azure Instance does not use basic authentication(Use SSH Key Instead)"
  },
  "CKV_AZURE_151": {
    "display_name": "CKV_AZURE_151",
    "severity": "1",
    "description": "Ensure Windows VM enables encryption",
    "categories": [
      "security"
    ],
    "title": "Ensure Windows VM enables encryption"
  },
  "CKV_AZURE_109": {
    "display_name": "CKV_AZURE_109",
    "severity": "1",
    "description": "Ensure that key vault allows firewall rules settings",
    "categories": [
      "security"
    ],
    "title": "Ensure that key vault allows firewall rules settings"
  },
  "CKV_AZURE_110": {
    "display_name": "CKV_AZURE_110",
    "severity": "1",
    "description": "Ensure that key vault enables purge protection",
    "categories": [
      "security"
    ],
    "title": "Ensure that key vault enables purge protection"
  },
  "CKV_AZURE_42": {
    "display_name": "CKV_AZURE_42",
    "severity": "1",
    "description": "Ensure the key vault is recoverable",
    "categories": [
      "security"
    ],
    "title": "Ensure the key vault is recoverable"
  },
  "CKV_AZURE_40": {
    "display_name": "CKV_AZURE_40",
    "severity": "1",
    "description": "Ensure that the expiration date is set on all keys",
    "categories": [
      "security"
    ],
    "title": "Ensure that the expiration date is set on all keys"
  },
  "CKV_AZURE_112": {
    "display_name": "CKV_AZURE_112",
    "severity": "1",
    "description": "Ensure that key vault key is backed by HSM",
    "categories": [
      "security"
    ],
    "title": "Ensure that key vault key is backed by HSM"
  },
  "CKV_AZURE_41": {
    "display_name": "CKV_AZURE_41",
    "severity": "1",
    "description": "Ensure that the expiration date is set on all secrets",
    "categories": [
      "security"
    ],
    "title": "Ensure that the expiration date is set on all secrets"
  },
  "CKV_AZURE_114": {
    "display_name": "CKV_AZURE_114",
    "severity": "1",
    "description": "Ensure that key vault secrets have \"content_type\" set",
    "categories": [
      "security"
    ],
    "title": "Ensure that key vault secrets have \"content_type\" set"
  },
  "CKV_AZURE_37": {
    "display_name": "CKV_AZURE_37",
    "severity": "1",
    "description": "Ensure that Activity Log Retention is set 365 days or greater",
    "categories": [
      "security"
    ],
    "title": "Ensure that Activity Log Retention is set 365 days or greater"
  },
  "CKV_AZURE_38": {
    "display_name": "CKV_AZURE_38",
    "severity": "1",
    "description": "Ensure audit profile captures all the activities",
    "categories": [
      "security"
    ],
    "title": "Ensure audit profile captures all the activities"
  },
  "CKV_AZURE_44": {
    "display_name": "CKV_AZURE_44",
    "severity": "1",
    "description": "Ensure Storage Account is using the latest version of TLS encryption",
    "categories": [
      "security"
    ],
    "title": "Ensure Storage Account is using the latest version of TLS encryption"
  },
  "CKV_AZURE_35": {
    "display_name": "CKV_AZURE_35",
    "severity": "1",
    "description": "Ensure default network access rule for Storage Accounts is set to deny",
    "categories": [
      "security"
    ],
    "title": "Ensure default network access rule for Storage Accounts is set to deny"
  },
  "CKV_AZURE_33": {
    "display_name": "CKV_AZURE_33",
    "severity": "1",
    "description": "Ensure Storage logging is enabled for Queue service for read, write and delete requests",
    "categories": [
      "security"
    ],
    "title": "Ensure Storage logging is enabled for Queue service for read, write and delete requests"
  },
  "CKV_AZURE_113": {
    "display_name": "CKV_AZURE_113",
    "severity": "1",
    "description": "Ensure that SQL server disables public network access",
    "categories": [
      "security"
    ],
    "title": "Ensure that SQL server disables public network access"
  },
  "CKV_AZURE_52": {
    "display_name": "CKV_AZURE_52",
    "severity": "1",
    "description": "Ensure MSSQL is using the latest version of TLS encryption",
    "categories": [
      "security"
    ],
    "title": "Ensure MSSQL is using the latest version of TLS encryption"
  },
  "CKV_AZURE_25": {
    "display_name": "CKV_AZURE_25",
    "severity": "1",
    "description": "Ensure that 'Threat Detection types' is set to 'All'",
    "categories": [
      "security"
    ],
    "title": "Ensure that 'Threat Detection types' is set to 'All'"
  },
  "CKV_AZURE_27": {
    "display_name": "CKV_AZURE_27",
    "severity": "1",
    "description": "Ensure that 'Email service and co-administrators' is 'Enabled' for MSSQL servers",
    "categories": [
      "security"
    ],
    "title": "Ensure that 'Email service and co-administrators' is 'Enabled' for MSSQL servers"
  },
  "CKV_AZURE_26": {
    "display_name": "CKV_AZURE_26",
    "severity": "1",
    "description": "Ensure that 'Send Alerts To' is enabled for MSSQL servers",
    "categories": [
      "security"
    ],
    "title": "Ensure that 'Send Alerts To' is enabled for MSSQL servers"
  },
  "CKV_AZURE_9": {
    "display_name": "CKV_AZURE_9",
    "severity": "1",
    "description": "Ensure that RDP access is restricted from the internet",
    "categories": [
      "security"
    ],
    "title": "Ensure that RDP access is restricted from the internet"
  },
  "CKV_AZURE_10": {
    "display_name": "CKV_AZURE_10",
    "severity": "1",
    "description": "Ensure that SSH access is restricted from the internet",
    "categories": [
      "security"
    ],
    "title": "Ensure that SSH access is restricted from the internet"
  },
  "CKV_AZURE_12": {
    "display_name": "CKV_AZURE_12",
    "severity": "1",
    "description": "Ensure that Network Security Group Flow Log retention period is 'greater than 90 days'",
    "categories": [
      "security"
    ],
    "title": "Ensure that Network Security Group Flow Log retention period is 'greater than 90 days'"
  },
  "CKV_AZURE_39": {
    "display_name": "CKV_AZURE_39",
    "severity": "1",
    "description": "Ensure that no custom subscription owner roles are created",
    "categories": [
      "security"
    ],
    "title": "Ensure that no custom subscription owner roles are created"
  },
  "CKV_AZURE_19": {
    "display_name": "CKV_AZURE_19",
    "severity": "1",
    "description": "Ensure that standard pricing tier is selected",
    "categories": [
      "security"
    ],
    "title": "Ensure that standard pricing tier is selected"
  },
  "CKV_AZURE_21": {
    "display_name": "CKV_AZURE_21",
    "severity": "1",
    "description": "Ensure that 'Send email notification for high severity alerts' is set to 'On'",
    "categories": [
      "security"
    ],
    "title": "Ensure that 'Send email notification for high severity alerts' is set to 'On'"
  },
  "CKV_AZURE_22": {
    "display_name": "CKV_AZURE_22",
    "severity": "1",
    "description": "Ensure that 'Send email notification for high severity alerts' is set to 'On'",
    "categories": [
      "security"
    ],
    "title": "Ensure that 'Send email notification for high severity alerts' is set to 'On'"
  },
  "CKV_AZURE_20": {
    "display_name": "CKV_AZURE_20",
    "severity": "1",
    "description": "Ensure that security contact 'Phone number' is set",
    "categories": [
      "security"
    ],
    "title": "Ensure that security contact 'Phone number' is set"
  },
  "CKV_AZURE_53": {
    "display_name": "CKV_AZURE_53",
    "severity": "1",
    "description": "Ensure 'public network access enabled' is set to 'False' for mySQL servers",
    "categories": [
      "security"
    ],
    "title": "Ensure 'public network access enabled' is set to 'False' for mySQL servers"
  },
  "CKV_AZURE_54": {
    "display_name": "CKV_AZURE_54",
    "severity": "1",
    "description": "Ensure MySQL is using the latest version of TLS encryption",
    "categories": [
      "security"
    ],
    "title": "Ensure MySQL is using the latest version of TLS encryption"
  },
  "CKV_AZURE_94": {
    "display_name": "CKV_AZURE_94",
    "severity": "1",
    "description": "Ensure that My SQL server enables geo-redundant backups",
    "categories": [
      "security"
    ],
    "title": "Ensure that My SQL server enables geo-redundant backups"
  },
  "CKV_AZURE_127": {
    "display_name": "CKV_AZURE_127",
    "severity": "1",
    "description": "Ensure that My SQL server enables Threat detection policy",
    "categories": [
      "security"
    ],
    "title": "Ensure that My SQL server enables Threat detection policy"
  },
  "CKV_AZURE_28": {
    "display_name": "CKV_AZURE_28",
    "severity": "1",
    "description": "Ensure 'Enforce SSL connection' is set to 'ENABLED' for MySQL Database Server",
    "categories": [
      "security"
    ],
    "title": "Ensure 'Enforce SSL connection' is set to 'ENABLED' for MySQL Database Server"
  },
  "CKV_AZURE_130": {
    "display_name": "CKV_AZURE_130",
    "severity": "1",
    "description": "Ensure that PostgreSQL server enables infrastructure encryption",
    "categories": [
      "security"
    ],
    "title": "Ensure that PostgreSQL server enables infrastructure encryption"
  },
  "CKV_AZURE_128": {
    "display_name": "CKV_AZURE_128",
    "severity": "1",
    "description": "Ensure that PostgreSQL server enables Threat detection policy",
    "categories": [
      "security"
    ],
    "title": "Ensure that PostgreSQL server enables Threat detection policy"
  },
  "CKV_AZURE_29": {
    "display_name": "CKV_AZURE_29",
    "severity": "1",
    "description": "Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server",
    "categories": [
      "security"
    ],
    "title": "Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server"
  },
  "CKV_AZURE_147": {
    "display_name": "CKV_AZURE_147",
    "severity": "1",
    "description": "Ensure PostgreSQL is using the latest version of TLS encryption",
    "categories": [
      "security"
    ],
    "title": "Ensure PostgreSQL is using the latest version of TLS encryption"
  },
  "CKV_AZURE_102": {
    "display_name": "CKV_AZURE_102",
    "severity": "1",
    "description": "Ensure that PostgreSQL server enables geo-redundant backups",
    "categories": [
      "security"
    ],
    "title": "Ensure that PostgreSQL server enables geo-redundant backups"
  },
  "CKV_AZURE_68": {
    "display_name": "CKV_AZURE_68",
    "severity": "1",
    "description": "Ensure that PostgreSQL server disables public network access",
    "categories": [
      "security"
    ],
    "title": "Ensure that PostgreSQL server disables public network access"
  },
  "CKV_AZURE_32": {
    "display_name": "CKV_AZURE_32",
    "severity": "1",
    "description": "Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server",
    "categories": [
      "security"
    ],
    "title": "Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server"
  },
  "CKV_AZURE_30": {
    "display_name": "CKV_AZURE_30",
    "severity": "1",
    "description": "Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server",
    "categories": [
      "security"
    ],
    "title": "Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server"
  },
  "CKV_AZURE_2": {
    "display_name": "CKV_AZURE_2",
    "severity": "1",
    "description": "Ensure Azure managed disk has encryption enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure Azure managed disk has encryption enabled"
  },
  "CKV_AZURE_93": {
    "display_name": "CKV_AZURE_93",
    "severity": "1",
    "description": "Ensure that managed disks use a specific set of disk encryption sets for the customer-managed key encryption",
    "categories": [
      "security"
    ],
    "title": "Ensure that managed disks use a specific set of disk encryption sets for the customer-managed key encryption"
  },
  "CKV_AZURE_3": {
    "display_name": "CKV_AZURE_3",
    "severity": "1",
    "description": "Ensure that 'Secure transfer required' is set to 'Enabled'",
    "categories": [
      "security"
    ],
    "title": "Ensure that 'Secure transfer required' is set to 'Enabled'"
  },
  "CKV_AZURE_36": {
    "display_name": "CKV_AZURE_36",
    "severity": "1",
    "description": "Ensure 'Trusted Microsoft Services' is enabled for Storage Account access",
    "categories": [
      "security"
    ],
    "title": "Ensure 'Trusted Microsoft Services' is enabled for Storage Account access"
  },
  "CKV_GCP_11": {
    "display_name": "CKV_GCP_11",
    "severity": "1",
    "description": "Ensure that Cloud SQL database Instances are not open to the world",
    "categories": [
      "security"
    ],
    "title": "Ensure that Cloud SQL database Instances are not open to the world"
  },
  "CKV_GCP_14": {
    "display_name": "CKV_GCP_14",
    "severity": "1",
    "description": "Ensure all Cloud SQL database instance have backup configuration enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure all Cloud SQL database instance have backup configuration enabled"
  },
  "CKV_GCP_79": {
    "display_name": "CKV_GCP_79",
    "severity": "1",
    "description": "Ensure SQL database is using latest Major version",
    "categories": [
      "security"
    ],
    "title": "Ensure SQL database is using latest Major version"
  },
  "CKV_GCP_6": {
    "display_name": "CKV_GCP_6",
    "severity": "1",
    "description": "Ensure all Cloud SQL database instance requires all incoming connections to use SSL",
    "categories": [
      "security"
    ],
    "title": "Ensure all Cloud SQL database instance requires all incoming connections to use SSL"
  },
  "CKV_GCP_60": {
    "display_name": "CKV_GCP_60",
    "severity": "1",
    "description": "Ensure Cloud SQL database does not have public IP",
    "categories": [
      "security"
    ],
    "title": "Ensure Cloud SQL database does not have public IP"
  },
  "CKV_GCP_15": {
    "display_name": "CKV_GCP_15",
    "severity": "1",
    "description": "Ensure that BigQuery datasets are not anonymously or publicly accessible",
    "categories": [
      "security"
    ],
    "title": "Ensure that BigQuery datasets are not anonymously or publicly accessible"
  },
  "CKV_GCP_81": {
    "display_name": "CKV_GCP_81",
    "severity": "1",
    "description": "Ensure Big Query Tables are encrypted with Customer Supplied Encryption Keys (CSEK)",
    "categories": [
      "security"
    ],
    "title": "Ensure Big Query Tables are encrypted with Customer Supplied Encryption Keys (CSEK)"
  },
  "CKV_GCP_78": {
    "display_name": "CKV_GCP_78",
    "severity": "1",
    "description": "Ensure Cloud storage has versioning enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure Cloud storage has versioning enabled"
  },
  "CKV_GCP_29": {
    "display_name": "CKV_GCP_29",
    "severity": "1",
    "description": "Ensure that Cloud Storage buckets have uniform bucket-level access enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure that Cloud Storage buckets have uniform bucket-level access enabled"
  },
  "CKV_GCP_62": {
    "display_name": "CKV_GCP_62",
    "severity": "1",
    "description": "Bucket should log access",
    "categories": [
      "security"
    ],
    "title": "Bucket should log access"
  },
  "CKV_GCP_28": {
    "display_name": "CKV_GCP_28",
    "severity": "1",
    "description": "Ensure that Cloud Storage bucket is not anonymously or publicly accessible",
    "categories": [
      "security"
    ],
    "title": "Ensure that Cloud Storage bucket is not anonymously or publicly accessible"
  },
  "CKV_GCP_66": {
    "display_name": "CKV_GCP_66",
    "severity": "1",
    "description": "Ensure use of Binary Authorization",
    "categories": [
      "security"
    ],
    "title": "Ensure use of Binary Authorization"
  },
  "CKV_GCP_19": {
    "display_name": "CKV_GCP_19",
    "severity": "1",
    "description": "Ensure GKE basic auth is disabled",
    "categories": [
      "security"
    ],
    "title": "Ensure GKE basic auth is disabled"
  },
  "CKV_GCP_21": {
    "display_name": "CKV_GCP_21",
    "severity": "1",
    "description": "Ensure Kubernetes Clusters are configured with Labels",
    "categories": [
      "security"
    ],
    "title": "Ensure Kubernetes Clusters are configured with Labels"
  },
  "CKV_GCP_24": {
    "display_name": "CKV_GCP_24",
    "severity": "1",
    "description": "Ensure PodSecurityPolicy controller is enabled on the Kubernetes Engine Clusters",
    "categories": [
      "security"
    ],
    "title": "Ensure PodSecurityPolicy controller is enabled on the Kubernetes Engine Clusters"
  },
  "CKV_GCP_12": {
    "display_name": "CKV_GCP_12",
    "severity": "1",
    "description": "Ensure Network Policy is enabled on Kubernetes Engine Clusters",
    "categories": [
      "security"
    ],
    "title": "Ensure Network Policy is enabled on Kubernetes Engine Clusters"
  },
  "CKV_GCP_65": {
    "display_name": "CKV_GCP_65",
    "severity": "1",
    "description": "Manage Kubernetes RBAC users with Google Groups for GKE",
    "categories": [
      "security"
    ],
    "title": "Manage Kubernetes RBAC users with Google Groups for GKE"
  },
  "CKV_GCP_7": {
    "display_name": "CKV_GCP_7",
    "severity": "1",
    "description": "Ensure Legacy Authorization is set to Disabled on Kubernetes Engine Clusters",
    "categories": [
      "security"
    ],
    "title": "Ensure Legacy Authorization is set to Disabled on Kubernetes Engine Clusters"
  },
  "CKV_GCP_70": {
    "display_name": "CKV_GCP_70",
    "severity": "1",
    "description": "Ensure the GKE Release Channel is set",
    "categories": [
      "security"
    ],
    "title": "Ensure the GKE Release Channel is set"
  },
  "CKV_GCP_8": {
    "display_name": "CKV_GCP_8",
    "severity": "1",
    "description": "Ensure Stackdriver Monitoring is set to Enabled on Kubernetes Engine Clusters",
    "categories": [
      "security"
    ],
    "title": "Ensure Stackdriver Monitoring is set to Enabled on Kubernetes Engine Clusters"
  },
  "CKV_GCP_25": {
    "display_name": "CKV_GCP_25",
    "severity": "1",
    "description": "Ensure Kubernetes Cluster is created with Private cluster enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure Kubernetes Cluster is created with Private cluster enabled"
  },
  "CKV_GCP_64": {
    "display_name": "CKV_GCP_64",
    "severity": "1",
    "description": "Ensure clusters are created with Private Nodes",
    "categories": [
      "security"
    ],
    "title": "Ensure clusters are created with Private Nodes"
  },
  "CKV_GCP_13": {
    "display_name": "CKV_GCP_13",
    "severity": "1",
    "description": "Ensure client certificate authentication to Kubernetes Engine Clusters is disabled",
    "categories": [
      "security"
    ],
    "title": "Ensure client certificate authentication to Kubernetes Engine Clusters is disabled"
  },
  "CKV_GCP_18": {
    "display_name": "CKV_GCP_18",
    "severity": "1",
    "description": "Ensure GKE Control Plane is not public",
    "categories": [
      "security"
    ],
    "title": "Ensure GKE Control Plane is not public"
  },
  "CKV_GCP_23": {
    "display_name": "CKV_GCP_23",
    "severity": "1",
    "description": "Ensure Kubernetes Cluster is created with Alias IP ranges enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure Kubernetes Cluster is created with Alias IP ranges enabled"
  },
  "CKV_GCP_1": {
    "display_name": "CKV_GCP_1",
    "severity": "1",
    "description": "Ensure Stackdriver Logging is set to Enabled on Kubernetes Engine Clusters",
    "categories": [
      "security"
    ],
    "title": "Ensure Stackdriver Logging is set to Enabled on Kubernetes Engine Clusters"
  },
  "CKV_GCP_61": {
    "display_name": "CKV_GCP_61",
    "severity": "1",
    "description": "Enable VPC Flow Logs and Intranode Visibility",
    "categories": [
      "security"
    ],
    "title": "Enable VPC Flow Logs and Intranode Visibility"
  },
  "CKV_GCP_69": {
    "display_name": "CKV_GCP_69",
    "severity": "1",
    "description": "Ensure the GKE Metadata Server is Enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure the GKE Metadata Server is Enabled"
  },
  "CKV_GCP_67": {
    "display_name": "CKV_GCP_67",
    "severity": "1",
    "description": "Ensure legacy Compute Engine instance metadata APIs are Disabled",
    "categories": [
      "security"
    ],
    "title": "Ensure legacy Compute Engine instance metadata APIs are Disabled"
  },
  "CKV_GCP_22": {
    "display_name": "CKV_GCP_22",
    "severity": "1",
    "description": "Ensure Container-Optimized OS (cos) is used for Kubernetes Engine Clusters Node image",
    "categories": [
      "security"
    ],
    "title": "Ensure Container-Optimized OS (cos) is used for Kubernetes Engine Clusters Node image"
  },
  "CKV_GCP_68": {
    "display_name": "CKV_GCP_68",
    "severity": "1",
    "description": "Ensure Secure Boot for Shielded GKE Nodes is Enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure Secure Boot for Shielded GKE Nodes is Enabled"
  },
  "CKV_GCP_10": {
    "display_name": "CKV_GCP_10",
    "severity": "1",
    "description": "Ensure 'Automatic node upgrade' is enabled for Kubernetes Clusters",
    "categories": [
      "security"
    ],
    "title": "Ensure 'Automatic node upgrade' is enabled for Kubernetes Clusters"
  },
  "CKV_GCP_9": {
    "display_name": "CKV_GCP_9",
    "severity": "1",
    "description": "Ensure 'Automatic node repair' is enabled for Kubernetes Clusters",
    "categories": [
      "security"
    ],
    "title": "Ensure 'Automatic node repair' is enabled for Kubernetes Clusters"
  },
  "CKV_GCP_39": {
    "display_name": "CKV_GCP_39",
    "severity": "1",
    "description": "Ensure Compute instances are launched with Shielded VM enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure Compute instances are launched with Shielded VM enabled"
  },
  "CKV_GCP_34": {
    "display_name": "CKV_GCP_34",
    "severity": "1",
    "description": "Ensure that no instance in the project overrides the project setting for enabling OSLogin(OSLogin needs to be enabled in project metadata for all instances)",
    "categories": [
      "security"
    ],
    "title": "Ensure that no instance in the project overrides the project setting for enabling OSLogin(OSLogin needs to be enabled in project metadata for all instances)"
  },
  "CKV_GCP_30": {
    "display_name": "CKV_GCP_30",
    "severity": "1",
    "description": "Ensure that instances are not configured to use the default service account",
    "categories": [
      "security"
    ],
    "title": "Ensure that instances are not configured to use the default service account"
  },
  "CKV_GCP_32": {
    "display_name": "CKV_GCP_32",
    "severity": "1",
    "description": "Ensure 'Block Project-wide SSH keys' is enabled for VM instances",
    "categories": [
      "security"
    ],
    "title": "Ensure 'Block Project-wide SSH keys' is enabled for VM instances"
  },
  "CKV_GCP_36": {
    "display_name": "CKV_GCP_36",
    "severity": "1",
    "description": "Ensure that IP forwarding is not enabled on Instances",
    "categories": [
      "security"
    ],
    "title": "Ensure that IP forwarding is not enabled on Instances"
  },
  "CKV_GCP_35": {
    "display_name": "CKV_GCP_35",
    "severity": "1",
    "description": "Ensure 'Enable connecting to serial ports' is not enabled for VM Instance",
    "categories": [
      "security"
    ],
    "title": "Ensure 'Enable connecting to serial ports' is not enabled for VM Instance"
  },
  "CKV_GCP_40": {
    "display_name": "CKV_GCP_40",
    "severity": "1",
    "description": "Ensure that Compute instances do not have public IP addresses",
    "categories": [
      "security"
    ],
    "title": "Ensure that Compute instances do not have public IP addresses"
  },
  "CKV_GCP_38": {
    "display_name": "CKV_GCP_38",
    "severity": "1",
    "description": "Ensure VM disks for critical VMs are encrypted with Customer Supplied Encryption Keys (CSEK)",
    "categories": [
      "security"
    ],
    "title": "Ensure VM disks for critical VMs are encrypted with Customer Supplied Encryption Keys (CSEK)"
  },
  "CKV_GCP_37": {
    "display_name": "CKV_GCP_37",
    "severity": "1",
    "description": "Ensure VM disks for critical VMs are encrypted with Customer Supplied Encryption Keys (CSEK)",
    "categories": [
      "security"
    ],
    "title": "Ensure VM disks for critical VMs are encrypted with Customer Supplied Encryption Keys (CSEK)"
  },
  "CKV_GCP_76": {
    "display_name": "CKV_GCP_76",
    "severity": "1",
    "description": "Ensure that Private google access is enabled for IPV6",
    "categories": [
      "security"
    ],
    "title": "Ensure that Private google access is enabled for IPV6"
  },
  "CKV_GCP_26": {
    "display_name": "CKV_GCP_26",
    "severity": "1",
    "description": "Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network",
    "categories": [
      "security"
    ],
    "title": "Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network"
  },
  "CKV_GCP_74": {
    "display_name": "CKV_GCP_74",
    "severity": "1",
    "description": "Ensure that private_ip_google_access is enabled for Subnet",
    "categories": [
      "security"
    ],
    "title": "Ensure that private_ip_google_access is enabled for Subnet"
  },
  "CKV_GCP_75": {
    "display_name": "CKV_GCP_75",
    "severity": "1",
    "description": "Ensure Google compute firewall ingress does not allow unrestricted FTP access",
    "categories": [
      "security"
    ],
    "title": "Ensure Google compute firewall ingress does not allow unrestricted FTP access"
  },
  "CKV_GCP_77": {
    "display_name": "CKV_GCP_77",
    "severity": "1",
    "description": "Ensure Google compute firewall ingress does not allow on ftp port",
    "categories": [
      "security"
    ],
    "title": "Ensure Google compute firewall ingress does not allow on ftp port"
  },
  "CKV_GCP_2": {
    "display_name": "CKV_GCP_2",
    "severity": "1",
    "description": "Ensure Google compute firewall ingress does not allow unrestricted ssh access",
    "categories": [
      "security"
    ],
    "title": "Ensure Google compute firewall ingress does not allow unrestricted ssh access"
  },
  "CKV_GCP_88": {
    "display_name": "CKV_GCP_88",
    "severity": "1",
    "description": "Ensure Google compute firewall ingress does not allow unrestricted mysql access",
    "categories": [
      "security"
    ],
    "title": "Ensure Google compute firewall ingress does not allow unrestricted mysql access"
  },
  "CKV_GCP_3": {
    "display_name": "CKV_GCP_3",
    "severity": "1",
    "description": "Ensure Google compute firewall ingress does not allow unrestricted rdp access",
    "categories": [
      "security"
    ],
    "title": "Ensure Google compute firewall ingress does not allow unrestricted rdp access"
  },
  "CKV_OCI_10": {
    "display_name": "CKV_OCI_10",
    "severity": "1",
    "description": "Ensure OCI Object Storage is not Public",
    "categories": [
      "security"
    ],
    "title": "Ensure OCI Object Storage is not Public"
  },
  "CKV_OCI_8": {
    "display_name": "CKV_OCI_8",
    "severity": "1",
    "description": "Ensure OCI Object Storage has versioning enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure OCI Object Storage has versioning enabled"
  },
  "CKV_OCI_9": {
    "display_name": "CKV_OCI_9",
    "severity": "1",
    "description": "Ensure OCI Object Storage is encrypted with Customer Managed Key",
    "categories": [
      "security"
    ],
    "title": "Ensure OCI Object Storage is encrypted with Customer Managed Key"
  },
  "CKV_OCI_7": {
    "display_name": "CKV_OCI_7",
    "severity": "1",
    "description": "Ensure OCI Object Storage bucket can emit object events",
    "categories": [
      "security"
    ],
    "title": "Ensure OCI Object Storage bucket can emit object events"
  },
  "CKV2_AWS_11": {
    "display_name": "CKV2_AWS_11",
    "severity": "1",
    "description": "Ensure VPC flow logging is enabled in all VPCs",
    "categories": [
      "security"
    ],
    "title": "Ensure VPC flow logging is enabled in all VPCs"
  },
  "CKV2_AWS_2": {
    "display_name": "CKV2_AWS_2",
    "severity": "1",
    "description": "Ensure that only encrypted EBS volumes are attached to EC2 instances",
    "categories": [
      "security"
    ],
    "title": "Ensure that only encrypted EBS volumes are attached to EC2 instances"
  },
  "CKV2_AWS_6": {
    "display_name": "CKV2_AWS_6",
    "severity": "1",
    "description": "Ensure that S3 bucket has a Public Access block",
    "categories": [
      "security"
    ],
    "title": "Ensure that S3 bucket has a Public Access block"
  },
  "CKV2_AWS_8": {
    "display_name": "CKV2_AWS_8",
    "severity": "1",
    "description": "Ensure that RDS clusters has backup plan of AWS Backup",
    "categories": [
      "security"
    ],
    "title": "Ensure that RDS clusters has backup plan of AWS Backup"
  },
  "CKV2_AWS_12": {
    "display_name": "CKV2_AWS_12",
    "severity": "1",
    "description": "Ensure the default security group of every VPC restricts all traffic",
    "categories": [
      "security"
    ],
    "title": "Ensure the default security group of every VPC restricts all traffic"
  },
  "CKV2_AZURE_1": {
    "display_name": "CKV2_AZURE_1",
    "severity": "1",
    "description": "Ensure storage for critical data are encrypted with Customer Managed Key",
    "categories": [
      "security"
    ],
    "title": "Ensure storage for critical data are encrypted with Customer Managed Key"
  },
  "CKV_AWS_18": {
    "display_name": "CKV_AWS_18",
    "severity": "1",
    "description": "Ensure the S3 bucket has access logging enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure the S3 bucket has access logging enabled"
  },
  "CKV_AZURE_120": {
    "display_name": "CKV_AZURE_120",
    "severity": "1",
    "description": "Ensure that Application Gateway enables WAF",
    "categories": [
      "security"
    ],
    "title": "Ensure that Application Gateway enables WAF"
  },
  "CKV2_AZURE_16": {
    "display_name": "CKV2_AZURE_16",
    "severity": "1",
    "description": "Ensure that MySQL server enables customer-managed key for encryption",
    "categories": [
      "security"
    ],
    "title": "Ensure that MySQL server enables customer-managed key for encryption"
  },
  "CKV2_AZURE_18": {
    "display_name": "CKV2_AZURE_18",
    "severity": "1",
    "description": "Ensure that Storage Accounts use customer-managed key for encryption",
    "categories": [
      "security"
    ],
    "title": "Ensure that Storage Accounts use customer-managed key for encryption"
  },
  "CKV_AZURE_24": {
    "display_name": "CKV_AZURE_24",
    "severity": "1",
    "description": "Ensure that 'Auditing' Retention is 'greater than 90 days' for SQL servers",
    "categories": [
      "security"
    ],
    "title": "Ensure that 'Auditing' Retention is 'greater than 90 days' for SQL servers"
  },
  "CKV2_AZURE_7": {
    "display_name": "CKV2_AZURE_7",
    "severity": "1",
    "description": "Ensure that Azure Active Directory Admin is configured",
    "categories": [
      "security"
    ],
    "title": "Ensure that Azure Active Directory Admin is configured"
  },
  "CKV_AWS_145": {
    "display_name": "CKV_AWS_145",
    "severity": "1",
    "description": "Ensure that S3 buckets are encrypted with KMS by default",
    "categories": [
      "security"
    ],
    "title": "Ensure that S3 buckets are encrypted with KMS by default"
  },
  "CKV_AWS_19": {
    "display_name": "CKV_AWS_19",
    "severity": "1",
    "description": "Ensure all data stored in the S3 bucket is securely encrypted at rest",
    "categories": [
      "security"
    ],
    "title": "Ensure all data stored in the S3 bucket is securely encrypted at rest"
  },
  "CKV_AWS_21": {
    "display_name": "CKV_AWS_21",
    "severity": "1",
    "description": "Ensure all data stored in the S3 bucket have versioning enabled",
    "categories": [
      "security"
    ],
    "title": "Ensure all data stored in the S3 bucket have versioning enabled"
  },
  "CKV_AZURE_23": {
    "display_name": "CKV_AZURE_23",
    "severity": "1",
    "description": "Ensure that 'Auditing' is set to 'On' for SQL servers",
    "categories": [
      "security"
    ],
    "title": "Ensure that 'Auditing' is set to 'On' for SQL servers"
  },
  "CKV_AWS_20": {
    "display_name": "CKV_AWS_20",
    "severity": "1",
    "description": "S3 Bucket has an ACL defined which allows public READ access.",
    "categories": [
      "security"
    ],
    "title": "S3 Bucket has an ACL defined which allows public READ access."
  },

  "CKV_K8S_49": {
    "title": "Minimize wildcard use in Roles and ClusterRoles",
    "display_name": "CKV_K8S_49",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Minimize wildcard use in Roles and ClusterRoles"
  },
  "CKV_K8S_43": {
    "title": "Image should use digest",
    "display_name": "CKV_K8S_43",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Image should use digest"
  },
  "CKV_K8S_40": {
    "title": "Containers should run as a high UID to avoid host conflict",
    "display_name": "CKV_K8S_40",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Containers should run as a high UID to avoid host conflict"
  },
  "CKV_K8S_25": {
    "title": "Minimize the admission of containers with added capability",
    "display_name": "CKV_K8S_25",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Minimize the admission of containers with added capability"
  },
  "CKV_K8S_27": {
    "title": "Do not expose the docker daemon socket to containers",
    "display_name": "CKV_K8S_27",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Do not expose the docker daemon socket to containers"
  },
  "CKV_K8S_20": {
    "title": "Containers should not run with allowPrivilegeEscalation",
    "display_name": "CKV_K8S_20",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Containers should not run with allowPrivilegeEscalation"
  },
  "CKV_K8S_21": {
    "title": "The default namespace should not be used",
    "display_name": "CKV_K8S_21",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "The default namespace should not be used"
  },
  "CKV_K8S_22": {
    "title": "Use read-only filesystem for containers where possible",
    "display_name": "CKV_K8S_22",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Use read-only filesystem for containers where possible"
  },
  "CKV_K8S_23": {
    "title": "Minimize the admission of root containers",
    "display_name": "CKV_K8S_23",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Minimize the admission of root containers"
  },
  "CKV_K8S_28": {
    "title": "Minimize the admission of containers with the NET_RAW capability",
    "display_name": "CKV_K8S_28",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Minimize the admission of containers with the NET_RAW capability"
  },
  "CKV_K8S_29": {
    "title": "Apply security context to your pods and containers",
    "display_name": "CKV_K8S_29",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Apply security context to your pods and containers"
  },
  "CKV_K8S_155": {
    "title": "Minimize ClusterRoles that grant control over validating or mutating admission webhook configurations",
    "display_name": "CKV_K8S_155",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Minimize ClusterRoles that grant control over validating or mutating admission webhook configurations"
  },
  "CKV_K8S_157": {
    "title": "Minimize Roles and ClusterRoles that grant permissions to bind RoleBindings or ClusterRoleBindings",
    "display_name": "CKV_K8S_157",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Minimize Roles and ClusterRoles that grant permissions to bind RoleBindings or ClusterRoleBindings"
  },
  "CKV_K8S_156": {
    "title": "Minimize ClusterRoles that grant permissions to approve CertificateSigningRequests",
    "display_name": "CKV_K8S_156",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Minimize ClusterRoles that grant permissions to approve CertificateSigningRequests"
  },
  "CKV_K8S_158": {
    "title": "Minimize Roles and ClusterRoles that grant permissions to escalate Roles or ClusterRoles",
    "display_name": "CKV_K8S_158",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Minimize Roles and ClusterRoles that grant permissions to escalate Roles or ClusterRoles"
  },
  "CKV_K8S_9": {
    "title": "Readiness Probe Should be Configured",
    "display_name": "CKV_K8S_9",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Readiness Probe Should be Configured"
  },
  "CKV_K8S_8": {
    "title": "Liveness Probe Should be Configured",
    "display_name": "CKV_K8S_8",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Liveness Probe Should be Configured"
  },
  "CKV_K8S_38": {
    "title": "Ensure that Service Account Tokens are only mounted where necessary",
    "display_name": "CKV_K8S_38",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Ensure that Service Account Tokens are only mounted where necessary"
  },
  "CKV_K8S_31": {
    "title": "Ensure that the seccomp profile is set to docker/default or runtime/default",
    "display_name": "CKV_K8S_31",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Ensure that the seccomp profile is set to docker/default or runtime/default"
  },
  "CKV_K8S_30": {
    "title": "Apply security context to your pods and containers",
    "display_name": "CKV_K8S_30",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Apply security context to your pods and containers"
  },
  "CKV_K8S_37": {
    "title": "Minimize the admission of containers with capabilities assigned",
    "display_name": "CKV_K8S_37",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Minimize the admission of containers with capabilities assigned"
  },
  "CKV_K8S_35": {
    "title": "Prefer using secrets as files over secrets as environment variables",
    "display_name": "CKV_K8S_35",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Prefer using secrets as files over secrets as environment variables"
  },
  "CKV_K8S_11": {
    "title": "CPU limits should be set",
    "display_name": "CKV_K8S_11",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "CPU limits should be set"
  },
  "CKV_K8S_10": {
    "title": "CPU requests should be set",
    "display_name": "CKV_K8S_10",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "CPU requests should be set"
  },
  "CKV_K8S_13": {
    "title": "Memory limits should be set",
    "display_name": "CKV_K8S_13",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Memory limits should be set"
  },
  "CKV_K8S_12": {
    "title": "Memory requests should be set",
    "display_name": "CKV_K8S_12",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Memory requests should be set"
  },
  "CKV_K8S_14": {
    "title": "Image Tag should be fixed - not latest or blank",
    "display_name": "CKV_K8S_14",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Image Tag should be fixed - not latest or blank"
  },
  "CKV_K8S_17": {
    "title": "Containers should not share the host process ID namespace",
    "display_name": "CKV_K8S_17",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Containers should not share the host process ID namespace"
  },
  "CKV_K8S_16": {
    "title": "Container should not be privileged",
    "display_name": "CKV_K8S_16",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Container should not be privileged"
  },
  "CKV_K8S_19": {
    "title": "Containers should not share the host network namespace",
    "display_name": "CKV_K8S_19",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Containers should not share the host network namespace"
  },
  "CKV_K8S_18": {
    "title": "Containers should not share the host IPC namespace",
    "display_name": "CKV_K8S_18",
    "severity": "1",
    "categories": [
      "security"
    ],
    "description": "Containers should not share the host IPC namespace"
  }
}


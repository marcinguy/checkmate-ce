issues_data = {   'CKV2_AWS_11': {   'categories': ['security'],
                       'description': 'Ensure VPC flow logging is enabled in '
                                      'all VPCs',
                       'display_name': 'CKV2_AWS_11',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure VPC flow logging is enabled in all '
                                'VPCs'},
    'CKV2_AWS_12': {   'categories': ['security'],
                       'description': 'Ensure the default security group of '
                                      'every VPC restricts all traffic',
                       'display_name': 'CKV2_AWS_12',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure the default security group of every '
                                'VPC restricts all traffic'},
    'CKV2_AWS_2': {   'categories': ['security'],
                      'description': 'Ensure that only encrypted EBS volumes '
                                     'are attached to EC2 instances',
                      'display_name': 'CKV2_AWS_2',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure that only encrypted EBS volumes are '
                               'attached to EC2 instances'},
    'CKV2_AWS_6': {   'categories': ['security'],
                      'description': 'Ensure that S3 bucket has a Public '
                                     'Access block',
                      'display_name': 'CKV2_AWS_6',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure that S3 bucket has a Public Access '
                               'block'},
    'CKV2_AWS_8': {   'categories': ['security'],
                      'description': 'Ensure that RDS clusters has backup plan '
                                     'of AWS Backup',
                      'display_name': 'CKV2_AWS_8',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure that RDS clusters has backup plan of '
                               'AWS Backup'},
    'CKV2_AZURE_1': {   'categories': ['security'],
                        'description': 'Ensure storage for critical data are '
                                       'encrypted with Customer Managed Key',
                        'display_name': 'CKV2_AZURE_1',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure storage for critical data are '
                                 'encrypted with Customer Managed Key'},
    'CKV2_AZURE_16': {   'categories': ['security'],
                         'description': 'Ensure that MySQL server enables '
                                        'customer-managed key for encryption',
                         'display_name': 'CKV2_AZURE_16',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ensure that MySQL server enables '
                                  'customer-managed key for encryption'},
    'CKV2_AZURE_18': {   'categories': ['security'],
                         'description': 'Ensure that Storage Accounts use '
                                        'customer-managed key for encryption',
                         'display_name': 'CKV2_AZURE_18',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ensure that Storage Accounts use '
                                  'customer-managed key for encryption'},
    'CKV2_AZURE_7': {   'categories': ['security'],
                        'description': 'Ensure that Azure Active Directory '
                                       'Admin is configured',
                        'display_name': 'CKV2_AZURE_7',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure that Azure Active Directory Admin is '
                                 'configured'},
    'CKV_ALI_1': {   'categories': ['security'],
                     'description': 'Alibaba Cloud OSS bucket accessible to '
                                    'public',
                     'display_name': 'CKV_ALI_1',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'Alibaba Cloud OSS bucket accessible to public'},
    'CKV_ALI_10': {   'categories': ['security'],
                      'description': 'Ensure OSS bucket has versioning enabled',
                      'display_name': 'CKV_ALI_10',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure OSS bucket has versioning enabled'},
    'CKV_ALI_11': {   'categories': ['security'],
                      'description': 'Ensure OSS bucket has transfer '
                                     'Acceleration enabled',
                      'display_name': 'CKV_ALI_11',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure OSS bucket has transfer Acceleration '
                               'enabled'},
    'CKV_ALI_12': {   'categories': ['security'],
                      'description': 'Ensure the OSS bucket has access logging '
                                     'enabled',
                      'display_name': 'CKV_ALI_12',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure the OSS bucket has access logging '
                               'enabled'},
    'CKV_ALI_20': {   'categories': ['security'],
                      'description': 'Ensure RDS instance uses SSL',
                      'display_name': 'CKV_ALI_20',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure RDS instance uses SSL'},
    'CKV_ALI_25': {   'categories': ['security'],
                      'description': 'Ensure RDS Instance SQL Collector '
                                     'Retention Period should be greater than '
                                     '180',
                      'display_name': 'CKV_ALI_25',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure RDS Instance SQL Collector Retention '
                               'Period should be greater than 180'},
    'CKV_ALI_4': {   'categories': ['security'],
                     'description': 'Ensure Action Trail Logging for all '
                                    'regions',
                     'display_name': 'CKV_ALI_4',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'Ensure Action Trail Logging for all regions'},
    'CKV_ALI_5': {   'categories': ['security'],
                     'description': 'Ensure Action Trail Logging for all '
                                    'events',
                     'display_name': 'CKV_ALI_5',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'Ensure Action Trail Logging for all events'},
    'CKV_ALI_6': {   'categories': ['security'],
                     'description': 'Ensure OSS bucket is encrypted with '
                                    'Customer Master Key',
                     'display_name': 'CKV_ALI_6',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'Ensure OSS bucket is encrypted with Customer '
                              'Master Key'},
    'CKV_ALI_9': {   'categories': ['security'],
                     'description': 'Ensure database instance is not public',
                     'display_name': 'CKV_ALI_9',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'Ensure database instance is not public'},
    'CKV_AWS_101': {   'categories': ['security'],
                       'description': 'Ensure Neptune logging is enabled',
                       'display_name': 'CKV_AWS_101',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure Neptune logging is enabled'},
    'CKV_AWS_109': {   'categories': ['security'],
                       'description': 'Ensure IAM policies does not allow '
                                      'permissions management / resource '
                                      'exposure without constraints',
                       'display_name': 'CKV_AWS_109',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure IAM policies does not allow '
                                'permissions management / resource exposure '
                                'without constraints'},
    'CKV_AWS_111': {   'categories': ['security'],
                       'description': 'Ensure IAM policies does not allow '
                                      'write access without constraints',
                       'display_name': 'CKV_AWS_111',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure IAM policies does not allow write '
                                'access without constraints'},
    'CKV_AWS_115': {   'categories': ['security'],
                       'description': 'Ensure that AWS Lambda function is '
                                      'configured for function-level '
                                      'concurrent execution limit',
                       'display_name': 'CKV_AWS_115',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure that AWS Lambda function is configured '
                                'for function-level concurrent execution '
                                'limit'},
    'CKV_AWS_116': {   'categories': ['security'],
                       'description': 'Ensure that AWS Lambda function is '
                                      'configured for a Dead Letter Queue(DLQ)',
                       'display_name': 'CKV_AWS_116',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure that AWS Lambda function is configured '
                                'for a Dead Letter Queue(DLQ)'},
    'CKV_AWS_117': {   'categories': ['security'],
                       'description': 'Ensure that AWS Lambda function is '
                                      'configured inside a VPC',
                       'display_name': 'CKV_AWS_117',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure that AWS Lambda function is configured '
                                'inside a VPC'},
    'CKV_AWS_118': {   'categories': ['security'],
                       'description': 'Ensure that enhanced monitoring is '
                                      'enabled for Amazon RDS instances',
                       'display_name': 'CKV_AWS_118',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure that enhanced monitoring is enabled '
                                'for Amazon RDS instances'},
    'CKV_AWS_126': {   'categories': ['security'],
                       'description': 'Ensure that detailed monitoring is '
                                      'enabled for EC2 instances',
                       'display_name': 'CKV_AWS_126',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure that detailed monitoring is enabled '
                                'for EC2 instances'},
    'CKV_AWS_127': {   'categories': ['security'],
                       'description': 'Ensure that Elastic Load Balancer(s) '
                                      'uses SSL certificates provided by AWS '
                                      'Certificate Manager',
                       'display_name': 'CKV_AWS_127',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure that Elastic Load Balancer(s) uses SSL '
                                'certificates provided by AWS Certificate '
                                'Manager'},
    'CKV_AWS_128': {   'categories': ['security'],
                       'description': 'Ensure that an Amazon RDS Clusters have '
                                      'AWS Identity and Access Management '
                                      '(IAM) authentication enabled',
                       'display_name': 'CKV_AWS_128',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure that an Amazon RDS Clusters have AWS '
                                'Identity and Access Management (IAM) '
                                'authentication enabled'},
    'CKV_AWS_129': {   'categories': ['security'],
                       'description': 'Ensure that respective logs of Amazon '
                                      'Relational Database Service (Amazon '
                                      'RDS) are enabled',
                       'display_name': 'CKV_AWS_129',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure that respective logs of Amazon '
                                'Relational Database Service (Amazon RDS) are '
                                'enabled'},
    'CKV_AWS_130': {   'categories': ['security'],
                       'description': 'Ensure VPC subnets do not assign public '
                                      'IP by default',
                       'display_name': 'CKV_AWS_130',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure VPC subnets do not assign public IP by '
                                'default'},
    'CKV_AWS_133': {   'categories': ['security'],
                       'description': 'Ensure that RDS instances has backup '
                                      'policy',
                       'display_name': 'CKV_AWS_133',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure that RDS instances has backup policy'},
    'CKV_AWS_135': {   'categories': ['security'],
                       'description': 'Ensure that EC2 is EBS optimized',
                       'display_name': 'CKV_AWS_135',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure that EC2 is EBS optimized'},
    'CKV_AWS_136': {   'categories': ['security'],
                       'description': 'Ensure that ECR repositories are '
                                      'encrypted using KMS',
                       'display_name': 'CKV_AWS_136',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure that ECR repositories are encrypted '
                                'using KMS'},
    'CKV_AWS_137': {   'categories': ['security'],
                       'description': 'Ensure that Elasticsearch is configured '
                                      'inside a VPC',
                       'display_name': 'CKV_AWS_137',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure that Elasticsearch is configured '
                                'inside a VPC'},
    'CKV_AWS_139': {   'categories': ['security'],
                       'description': 'Ensure that RDS clusters have deletion '
                                      'protection enabled',
                       'display_name': 'CKV_AWS_139',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure that RDS clusters have deletion '
                                'protection enabled'},
    'CKV_AWS_144': {   'categories': ['security'],
                       'description': 'Ensure that S3 bucket has cross-region '
                                      'replication enabled',
                       'display_name': 'CKV_AWS_144',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure that S3 bucket has cross-region '
                                'replication enabled'},
    'CKV_AWS_145': {   'categories': ['security'],
                       'description': 'Ensure that S3 buckets are encrypted '
                                      'with KMS by default',
                       'display_name': 'CKV_AWS_145',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure that S3 buckets are encrypted with KMS '
                                'by default'},
    'CKV_AWS_157': {   'categories': ['security'],
                       'description': 'Ensure that RDS instances have Multi-AZ '
                                      'enabled',
                       'display_name': 'CKV_AWS_157',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure that RDS instances have Multi-AZ '
                                'enabled'},
    'CKV_AWS_16': {   'categories': ['security'],
                      'description': 'Ensure all data stored in the RDS is '
                                     'securely encrypted at rest',
                      'display_name': 'CKV_AWS_16',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure all data stored in the RDS is securely '
                               'encrypted at rest'},
    'CKV_AWS_161': {   'categories': ['security'],
                       'description': 'Ensure RDS database has IAM '
                                      'authentication enabled',
                       'display_name': 'CKV_AWS_161',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure RDS database has IAM authentication '
                                'enabled'},
    'CKV_AWS_162': {   'categories': ['security'],
                       'description': 'Ensure RDS cluster has IAM '
                                      'authentication enabled',
                       'display_name': 'CKV_AWS_162',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure RDS cluster has IAM authentication '
                                'enabled'},
    'CKV_AWS_163': {   'categories': ['security'],
                       'description': 'Ensure ECR image scanning on push is '
                                      'enabled',
                       'display_name': 'CKV_AWS_163',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure ECR image scanning on push is enabled'},
    'CKV_AWS_17': {   'categories': ['security'],
                      'description': 'Ensure all data stored in RDS is not '
                                     'publicly accessible',
                      'display_name': 'CKV_AWS_17',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure all data stored in RDS is not publicly '
                               'accessible'},
    'CKV_AWS_173': {   'categories': ['security'],
                       'description': 'Check encryption settings for Lambda '
                                      'environmental variable',
                       'display_name': 'CKV_AWS_173',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Check encryption settings for Lambda '
                                'environmental variable'},
    'CKV_AWS_18': {   'categories': ['security'],
                      'description': 'Ensure the S3 bucket has access logging '
                                     'enabled',
                      'display_name': 'CKV_AWS_18',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure the S3 bucket has access logging '
                               'enabled'},
    'CKV_AWS_186': {   'categories': ['security'],
                       'description': 'Ensure S3 bucket Object is encrypted by '
                                      'KMS using a customer managed Key (CMK)',
                       'display_name': 'CKV_AWS_186',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure S3 bucket Object is encrypted by KMS '
                                'using a customer managed Key (CMK)'},
    'CKV_AWS_189': {   'categories': ['security'],
                       'description': 'Ensure EBS Volume is encrypted by KMS '
                                      'using a customer managed Key (CMK)',
                       'display_name': 'CKV_AWS_189',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure EBS Volume is encrypted by KMS using a '
                                'customer managed Key (CMK)'},
    'CKV_AWS_19': {   'categories': ['security'],
                      'description': 'Ensure all data stored in the S3 bucket '
                                     'is securely encrypted at rest',
                      'display_name': 'CKV_AWS_19',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure all data stored in the S3 bucket is '
                               'securely encrypted at rest'},
    'CKV_AWS_20': {   'categories': ['security'],
                      'description': 'S3 Bucket has an ACL defined which '
                                     'allows public READ access.',
                      'display_name': 'CKV_AWS_20',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'S3 Bucket has an ACL defined which allows '
                               'public READ access.'},
    'CKV_AWS_21': {   'categories': ['security'],
                      'description': 'Ensure all data stored in the S3 bucket '
                                     'have versioning enabled',
                      'display_name': 'CKV_AWS_21',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure all data stored in the S3 bucket have '
                               'versioning enabled'},
    'CKV_AWS_226': {   'categories': ['security'],
                       'description': 'Ensure DB instance gets all minor '
                                      'upgrades automatically',
                       'display_name': 'CKV_AWS_226',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure DB instance gets all minor upgrades '
                                'automatically'},
    'CKV_AWS_228': {   'categories': ['security'],
                       'description': 'Verify Elasticsearch domain is using an '
                                      'up to date TLS policy',
                       'display_name': 'CKV_AWS_228',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Verify Elasticsearch domain is using an up to '
                                'date TLS policy'},
    'CKV_AWS_23': {   'categories': ['security'],
                      'description': 'Ensure every security groups rule has a '
                                     'description',
                      'display_name': 'CKV_AWS_23',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure every security groups rule has a '
                               'description'},
    'CKV_AWS_24': {   'categories': ['security'],
                      'description': 'Ensure no security groups allow ingress '
                                     'from 0.0.0.0:0 to port 22',
                      'display_name': 'CKV_AWS_24',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure no security groups allow ingress from '
                               '0.0.0.0:0 to port 22'},
    'CKV_AWS_247': {   'categories': ['security'],
                       'description': 'Ensure all data stored in the '
                                      'Elasticsearch is encrypted with a CMK',
                       'display_name': 'CKV_AWS_247',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure all data stored in the Elasticsearch '
                                'is encrypted with a CMK'},
    'CKV_AWS_248': {   'categories': ['security'],
                       'description': 'Ensure that Elasticsearch is not using '
                                      'the default Security Group',
                       'display_name': 'CKV_AWS_248',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure that Elasticsearch is not using the '
                                'default Security Group'},
    'CKV_AWS_3': {   'categories': ['security'],
                     'description': 'Ensure all data stored in the EBS is '
                                    'securely encrypted',
                     'display_name': 'CKV_AWS_3',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'Ensure all data stored in the EBS is securely '
                              'encrypted'},
    'CKV_AWS_37': {   'categories': ['security'],
                      'description': 'Ensure Amazon EKS control plane logging '
                                     'enabled for all log types',
                      'display_name': 'CKV_AWS_37',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure Amazon EKS control plane logging '
                               'enabled for all log types'},
    'CKV_AWS_38': {   'categories': ['security'],
                      'description': 'Ensure Amazon EKS public endpoint not '
                                     'accessible to 0.0.0.0/0',
                      'display_name': 'CKV_AWS_38',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure Amazon EKS public endpoint not '
                               'accessible to 0.0.0.0/0'},
    'CKV_AWS_39': {   'categories': ['security'],
                      'description': 'Ensure Amazon EKS public endpoint '
                                     'disabled',
                      'display_name': 'CKV_AWS_39',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure Amazon EKS public endpoint disabled'},
    'CKV_AWS_41': {   'categories': ['security'],
                      'description': 'Ensure no hard coded AWS access key and '
                                     'secret key exists in provider',
                      'display_name': 'CKV_AWS_41',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure no hard coded AWS access key and secret '
                               'key exists in provider'},
    'CKV_AWS_44': {   'categories': ['security'],
                      'description': 'Ensure Neptune storage is securely '
                                     'encrypted',
                      'display_name': 'CKV_AWS_44',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure Neptune storage is securely encrypted'},
    'CKV_AWS_45': {   'categories': ['security'],
                      'description': 'Ensure no hard-coded secrets exist in '
                                     'lambda environment',
                      'display_name': 'CKV_AWS_45',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure no hard-coded secrets exist in lambda '
                               'environment'},
    'CKV_AWS_46': {   'categories': ['security'],
                      'description': 'Ensure no hard-coded secrets exist in '
                                     'EC2 user data',
                      'display_name': 'CKV_AWS_46',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure no hard-coded secrets exist in EC2 user '
                               'data'},
    'CKV_AWS_5': {   'categories': ['security'],
                     'description': 'Ensure all data stored in the '
                                    'Elasticsearch is securely encrypted at '
                                    'rest',
                     'display_name': 'CKV_AWS_5',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'Ensure all data stored in the Elasticsearch is '
                              'securely encrypted at rest'},
    'CKV_AWS_50': {   'categories': ['security'],
                      'description': 'X-ray tracing is enabled for Lambda',
                      'display_name': 'CKV_AWS_50',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'X-ray tracing is enabled for Lambda'},
    'CKV_AWS_51': {   'categories': ['security'],
                      'description': 'Ensure ECR Image Tags are immutable',
                      'display_name': 'CKV_AWS_51',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure ECR Image Tags are immutable'},
    'CKV_AWS_58': {   'categories': ['security'],
                      'description': 'Ensure EKS Cluster has Secrets '
                                     'Encryption Enabled',
                      'display_name': 'CKV_AWS_58',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure EKS Cluster has Secrets Encryption '
                               'Enabled'},
    'CKV_AWS_7': {   'categories': ['security'],
                     'description': 'Ensure rotation for customer created CMKs '
                                    'is enabled',
                     'display_name': 'CKV_AWS_7',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'Ensure rotation for customer created CMKs is '
                              'enabled'},
    'CKV_AWS_79': {   'categories': ['security'],
                      'description': 'Ensure Instance Metadata Service Version '
                                     '1 is not enabled',
                      'display_name': 'CKV_AWS_79',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure Instance Metadata Service Version 1 is '
                               'not enabled'},
    'CKV_AWS_8': {   'categories': ['security'],
                     'description': 'Ensure all data stored in the Launch '
                                    'configuration or instance Elastic Blocks '
                                    'Store is securely encrypted',
                     'display_name': 'CKV_AWS_8',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'Ensure all data stored in the Launch '
                              'configuration or instance Elastic Blocks Store '
                              'is securely encrypted'},
    'CKV_AWS_84': {   'categories': ['security'],
                      'description': 'Ensure Elasticsearch Domain Logging is '
                                     'enabled',
                      'display_name': 'CKV_AWS_84',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure Elasticsearch Domain Logging is '
                               'enabled'},
    'CKV_AWS_92': {   'categories': ['security'],
                      'description': 'Ensure the ELB has access logging '
                                     'enabled',
                      'display_name': 'CKV_AWS_92',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure the ELB has access logging enabled'},
    'CKV_AWS_96': {   'categories': ['security'],
                      'description': 'Ensure all data stored in Aurora is '
                                     'securely encrypted at rest',
                      'display_name': 'CKV_AWS_96',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure all data stored in Aurora is securely '
                               'encrypted at rest'},
    'CKV_AZURE_1': {   'categories': ['security'],
                       'description': 'Ensure Azure Instance does not use '
                                      'basic authentication(Use SSH Key '
                                      'Instead)',
                       'display_name': 'CKV_AZURE_1',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure Azure Instance does not use basic '
                                'authentication(Use SSH Key Instead)'},
    'CKV_AZURE_10': {   'categories': ['security'],
                        'description': 'Ensure that SSH access is restricted '
                                       'from the internet',
                        'display_name': 'CKV_AZURE_10',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure that SSH access is restricted from '
                                 'the internet'},
    'CKV_AZURE_102': {   'categories': ['security'],
                         'description': 'Ensure that PostgreSQL server enables '
                                        'geo-redundant backups',
                         'display_name': 'CKV_AZURE_102',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ensure that PostgreSQL server enables '
                                  'geo-redundant backups'},
    'CKV_AZURE_109': {   'categories': ['security'],
                         'description': 'Ensure that key vault allows firewall '
                                        'rules settings',
                         'display_name': 'CKV_AZURE_109',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ensure that key vault allows firewall rules '
                                  'settings'},
    'CKV_AZURE_110': {   'categories': ['security'],
                         'description': 'Ensure that key vault enables purge '
                                        'protection',
                         'display_name': 'CKV_AZURE_110',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ensure that key vault enables purge '
                                  'protection'},
    'CKV_AZURE_112': {   'categories': ['security'],
                         'description': 'Ensure that key vault key is backed '
                                        'by HSM',
                         'display_name': 'CKV_AZURE_112',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ensure that key vault key is backed by HSM'},
    'CKV_AZURE_113': {   'categories': ['security'],
                         'description': 'Ensure that SQL server disables '
                                        'public network access',
                         'display_name': 'CKV_AZURE_113',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ensure that SQL server disables public '
                                  'network access'},
    'CKV_AZURE_114': {   'categories': ['security'],
                         'description': 'Ensure that key vault secrets have '
                                        '"content_type" set',
                         'display_name': 'CKV_AZURE_114',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ensure that key vault secrets have '
                                  '"content_type" set'},
    'CKV_AZURE_115': {   'categories': ['security'],
                         'description': 'Ensure that AKS enables private '
                                        'clusters',
                         'display_name': 'CKV_AZURE_115',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ensure that AKS enables private clusters'},
    'CKV_AZURE_116': {   'categories': ['security'],
                         'description': 'Ensure that AKS uses Azure Policies '
                                        'Add-on',
                         'display_name': 'CKV_AZURE_116',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ensure that AKS uses Azure Policies Add-on'},
    'CKV_AZURE_117': {   'categories': ['security'],
                         'description': 'Ensure that AKS uses disk encryption '
                                        'set',
                         'display_name': 'CKV_AZURE_117',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ensure that AKS uses disk encryption set'},
    'CKV_AZURE_12': {   'categories': ['security'],
                        'description': 'Ensure that Network Security Group '
                                       "Flow Log retention period is 'greater "
                                       "than 90 days'",
                        'display_name': 'CKV_AZURE_12',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure that Network Security Group Flow Log '
                                 "retention period is 'greater than 90 days'"},
    'CKV_AZURE_120': {   'categories': ['security'],
                         'description': 'Ensure that Application Gateway '
                                        'enables WAF',
                         'display_name': 'CKV_AZURE_120',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ensure that Application Gateway enables '
                                  'WAF'},
    'CKV_AZURE_127': {   'categories': ['security'],
                         'description': 'Ensure that My SQL server enables '
                                        'Threat detection policy',
                         'display_name': 'CKV_AZURE_127',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ensure that My SQL server enables Threat '
                                  'detection policy'},
    'CKV_AZURE_128': {   'categories': ['security'],
                         'description': 'Ensure that PostgreSQL server enables '
                                        'Threat detection policy',
                         'display_name': 'CKV_AZURE_128',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ensure that PostgreSQL server enables '
                                  'Threat detection policy'},
    'CKV_AZURE_13': {   'categories': ['security'],
                        'description': 'Ensure App Service Authentication is '
                                       'set on Azure App Service',
                        'display_name': 'CKV_AZURE_13',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure App Service Authentication is set on '
                                 'Azure App Service'},
    'CKV_AZURE_130': {   'categories': ['security'],
                         'description': 'Ensure that PostgreSQL server enables '
                                        'infrastructure encryption',
                         'display_name': 'CKV_AZURE_130',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ensure that PostgreSQL server enables '
                                  'infrastructure encryption'},
    'CKV_AZURE_14': {   'categories': ['security'],
                        'description': 'Ensure web app redirects all HTTP '
                                       'traffic to HTTPS in Azure App Service',
                        'display_name': 'CKV_AZURE_14',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure web app redirects all HTTP traffic to '
                                 'HTTPS in Azure App Service'},
    'CKV_AZURE_141': {   'categories': ['security'],
                         'description': 'Ensure AKS local admin account is '
                                        'disabled',
                         'display_name': 'CKV_AZURE_141',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ensure AKS local admin account is disabled'},
    'CKV_AZURE_147': {   'categories': ['security'],
                         'description': 'Ensure PostgreSQL is using the latest '
                                        'version of TLS encryption',
                         'display_name': 'CKV_AZURE_147',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ensure PostgreSQL is using the latest '
                                  'version of TLS encryption'},
    'CKV_AZURE_149': {   'categories': ['security'],
                         'description': 'Ensure that Virtual machine does not '
                                        'enable password authentication',
                         'display_name': 'CKV_AZURE_149',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ensure that Virtual machine does not enable '
                                  'password authentication'},
    'CKV_AZURE_15': {   'categories': ['security'],
                        'description': 'Ensure web app is using the latest '
                                       'version of TLS encryption',
                        'display_name': 'CKV_AZURE_15',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure web app is using the latest version '
                                 'of TLS encryption'},
    'CKV_AZURE_151': {   'categories': ['security'],
                         'description': 'Ensure Windows VM enables encryption',
                         'display_name': 'CKV_AZURE_151',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '1',
                         'title': 'Ensure Windows VM enables encryption'},
    'CKV_AZURE_16': {   'categories': ['security'],
                        'description': 'Ensure that Register with Azure Active '
                                       'Directory is enabled on App Service',
                        'display_name': 'CKV_AZURE_16',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure that Register with Azure Active '
                                 'Directory is enabled on App Service'},
    'CKV_AZURE_17': {   'categories': ['security'],
                        'description': "Ensure the web app has 'Client "
                                       'Certificates (Incoming client '
                                       "certificates)' set",
                        'display_name': 'CKV_AZURE_17',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': "Ensure the web app has 'Client Certificates "
                                 "(Incoming client certificates)' set"},
    'CKV_AZURE_18': {   'categories': ['security'],
                        'description': "Ensure that 'HTTP Version' is the "
                                       'latest if used to run the web app',
                        'display_name': 'CKV_AZURE_18',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': "Ensure that 'HTTP Version' is the latest if "
                                 'used to run the web app'},
    'CKV_AZURE_19': {   'categories': ['security'],
                        'description': 'Ensure that standard pricing tier is '
                                       'selected',
                        'display_name': 'CKV_AZURE_19',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure that standard pricing tier is '
                                 'selected'},
    'CKV_AZURE_2': {   'categories': ['security'],
                       'description': 'Ensure Azure managed disk has '
                                      'encryption enabled',
                       'display_name': 'CKV_AZURE_2',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure Azure managed disk has encryption '
                                'enabled'},
    'CKV_AZURE_20': {   'categories': ['security'],
                        'description': "Ensure that security contact 'Phone "
                                       "number' is set",
                        'display_name': 'CKV_AZURE_20',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': "Ensure that security contact 'Phone number' "
                                 'is set'},
    'CKV_AZURE_21': {   'categories': ['security'],
                        'description': "Ensure that 'Send email notification "
                                       "for high severity alerts' is set to "
                                       "'On'",
                        'display_name': 'CKV_AZURE_21',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': "Ensure that 'Send email notification for "
                                 "high severity alerts' is set to 'On'"},
    'CKV_AZURE_22': {   'categories': ['security'],
                        'description': "Ensure that 'Send email notification "
                                       "for high severity alerts' is set to "
                                       "'On'",
                        'display_name': 'CKV_AZURE_22',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': "Ensure that 'Send email notification for "
                                 "high severity alerts' is set to 'On'"},
    'CKV_AZURE_23': {   'categories': ['security'],
                        'description': "Ensure that 'Auditing' is set to 'On' "
                                       'for SQL servers',
                        'display_name': 'CKV_AZURE_23',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': "Ensure that 'Auditing' is set to 'On' for "
                                 'SQL servers'},
    'CKV_AZURE_24': {   'categories': ['security'],
                        'description': "Ensure that 'Auditing' Retention is "
                                       "'greater than 90 days' for SQL servers",
                        'display_name': 'CKV_AZURE_24',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': "Ensure that 'Auditing' Retention is 'greater "
                                 "than 90 days' for SQL servers"},
    'CKV_AZURE_25': {   'categories': ['security'],
                        'description': "Ensure that 'Threat Detection types' "
                                       "is set to 'All'",
                        'display_name': 'CKV_AZURE_25',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': "Ensure that 'Threat Detection types' is set "
                                 "to 'All'"},
    'CKV_AZURE_26': {   'categories': ['security'],
                        'description': "Ensure that 'Send Alerts To' is "
                                       'enabled for MSSQL servers',
                        'display_name': 'CKV_AZURE_26',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': "Ensure that 'Send Alerts To' is enabled for "
                                 'MSSQL servers'},
    'CKV_AZURE_27': {   'categories': ['security'],
                        'description': "Ensure that 'Email service and "
                                       "co-administrators' is 'Enabled' for "
                                       'MSSQL servers',
                        'display_name': 'CKV_AZURE_27',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': "Ensure that 'Email service and "
                                 "co-administrators' is 'Enabled' for MSSQL "
                                 'servers'},
    'CKV_AZURE_28': {   'categories': ['security'],
                        'description': "Ensure 'Enforce SSL connection' is set "
                                       "to 'ENABLED' for MySQL Database Server",
                        'display_name': 'CKV_AZURE_28',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': "Ensure 'Enforce SSL connection' is set to "
                                 "'ENABLED' for MySQL Database Server"},
    'CKV_AZURE_29': {   'categories': ['security'],
                        'description': "Ensure 'Enforce SSL connection' is set "
                                       "to 'ENABLED' for PostgreSQL Database "
                                       'Server',
                        'display_name': 'CKV_AZURE_29',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': "Ensure 'Enforce SSL connection' is set to "
                                 "'ENABLED' for PostgreSQL Database Server"},
    'CKV_AZURE_3': {   'categories': ['security'],
                       'description': "Ensure that 'Secure transfer required' "
                                      "is set to 'Enabled'",
                       'display_name': 'CKV_AZURE_3',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': "Ensure that 'Secure transfer required' is set "
                                "to 'Enabled'"},
    'CKV_AZURE_30': {   'categories': ['security'],
                        'description': 'Ensure server parameter '
                                       "'log_checkpoints' is set to 'ON' for "
                                       'PostgreSQL Database Server',
                        'display_name': 'CKV_AZURE_30',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': "Ensure server parameter 'log_checkpoints' is "
                                 "set to 'ON' for PostgreSQL Database Server"},
    'CKV_AZURE_32': {   'categories': ['security'],
                        'description': 'Ensure server parameter '
                                       "'connection_throttling' is set to 'ON' "
                                       'for PostgreSQL Database Server',
                        'display_name': 'CKV_AZURE_32',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure server parameter '
                                 "'connection_throttling' is set to 'ON' for "
                                 'PostgreSQL Database Server'},
    'CKV_AZURE_33': {   'categories': ['security'],
                        'description': 'Ensure Storage logging is enabled for '
                                       'Queue service for read, write and '
                                       'delete requests',
                        'display_name': 'CKV_AZURE_33',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure Storage logging is enabled for Queue '
                                 'service for read, write and delete requests'},
    'CKV_AZURE_35': {   'categories': ['security'],
                        'description': 'Ensure default network access rule for '
                                       'Storage Accounts is set to deny',
                        'display_name': 'CKV_AZURE_35',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure default network access rule for '
                                 'Storage Accounts is set to deny'},
    'CKV_AZURE_36': {   'categories': ['security'],
                        'description': "Ensure 'Trusted Microsoft Services' is "
                                       'enabled for Storage Account access',
                        'display_name': 'CKV_AZURE_36',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': "Ensure 'Trusted Microsoft Services' is "
                                 'enabled for Storage Account access'},
    'CKV_AZURE_37': {   'categories': ['security'],
                        'description': 'Ensure that Activity Log Retention is '
                                       'set 365 days or greater',
                        'display_name': 'CKV_AZURE_37',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure that Activity Log Retention is set '
                                 '365 days or greater'},
    'CKV_AZURE_38': {   'categories': ['security'],
                        'description': 'Ensure audit profile captures all the '
                                       'activities',
                        'display_name': 'CKV_AZURE_38',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure audit profile captures all the '
                                 'activities'},
    'CKV_AZURE_39': {   'categories': ['security'],
                        'description': 'Ensure that no custom subscription '
                                       'owner roles are created',
                        'display_name': 'CKV_AZURE_39',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure that no custom subscription owner '
                                 'roles are created'},
    'CKV_AZURE_4': {   'categories': ['security'],
                       'description': 'Ensure AKS logging to Azure Monitoring '
                                      'is Configured',
                       'display_name': 'CKV_AZURE_4',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure AKS logging to Azure Monitoring is '
                                'Configured'},
    'CKV_AZURE_40': {   'categories': ['security'],
                        'description': 'Ensure that the expiration date is set '
                                       'on all keys',
                        'display_name': 'CKV_AZURE_40',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure that the expiration date is set on '
                                 'all keys'},
    'CKV_AZURE_41': {   'categories': ['security'],
                        'description': 'Ensure that the expiration date is set '
                                       'on all secrets',
                        'display_name': 'CKV_AZURE_41',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure that the expiration date is set on '
                                 'all secrets'},
    'CKV_AZURE_42': {   'categories': ['security'],
                        'description': 'Ensure the key vault is recoverable',
                        'display_name': 'CKV_AZURE_42',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure the key vault is recoverable'},
    'CKV_AZURE_44': {   'categories': ['security'],
                        'description': 'Ensure Storage Account is using the '
                                       'latest version of TLS encryption',
                        'display_name': 'CKV_AZURE_44',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure Storage Account is using the latest '
                                 'version of TLS encryption'},
    'CKV_AZURE_5': {   'categories': ['security'],
                       'description': 'Ensure RBAC is enabled on AKS clusters',
                       'display_name': 'CKV_AZURE_5',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure RBAC is enabled on AKS clusters'},
    'CKV_AZURE_50': {   'categories': ['security'],
                        'description': 'Ensure Virtual Machine Extensions are '
                                       'not Installed',
                        'display_name': 'CKV_AZURE_50',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure Virtual Machine Extensions are not '
                                 'Installed'},
    'CKV_AZURE_52': {   'categories': ['security'],
                        'description': 'Ensure MSSQL is using the latest '
                                       'version of TLS encryption',
                        'display_name': 'CKV_AZURE_52',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure MSSQL is using the latest version of '
                                 'TLS encryption'},
    'CKV_AZURE_53': {   'categories': ['security'],
                        'description': "Ensure 'public network access enabled' "
                                       "is set to 'False' for mySQL servers",
                        'display_name': 'CKV_AZURE_53',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': "Ensure 'public network access enabled' is "
                                 "set to 'False' for mySQL servers"},
    'CKV_AZURE_54': {   'categories': ['security'],
                        'description': 'Ensure MySQL is using the latest '
                                       'version of TLS encryption',
                        'display_name': 'CKV_AZURE_54',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure MySQL is using the latest version of '
                                 'TLS encryption'},
    'CKV_AZURE_6': {   'categories': ['security'],
                       'description': 'Ensure AKS has an API Server Authorized '
                                      'IP Ranges enabled',
                       'display_name': 'CKV_AZURE_6',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure AKS has an API Server Authorized IP '
                                'Ranges enabled'},
    'CKV_AZURE_63': {   'categories': ['security'],
                        'description': 'Ensure that App service enables HTTP '
                                       'logging',
                        'display_name': 'CKV_AZURE_63',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure that App service enables HTTP '
                                 'logging'},
    'CKV_AZURE_65': {   'categories': ['security'],
                        'description': 'Ensure that App service enables '
                                       'detailed error messages',
                        'display_name': 'CKV_AZURE_65',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure that App service enables detailed '
                                 'error messages'},
    'CKV_AZURE_66': {   'categories': ['security'],
                        'description': 'Ensure that App service enables failed '
                                       'request tracing',
                        'display_name': 'CKV_AZURE_66',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure that App service enables failed '
                                 'request tracing'},
    'CKV_AZURE_68': {   'categories': ['security'],
                        'description': 'Ensure that PostgreSQL server disables '
                                       'public network access',
                        'display_name': 'CKV_AZURE_68',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure that PostgreSQL server disables '
                                 'public network access'},
    'CKV_AZURE_7': {   'categories': ['security'],
                       'description': 'Ensure AKS cluster has Network Policy '
                                      'configured',
                       'display_name': 'CKV_AZURE_7',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure AKS cluster has Network Policy '
                                'configured'},
    'CKV_AZURE_71': {   'categories': ['security'],
                        'description': 'Ensure that Managed identity provider '
                                       'is enabled for app services',
                        'display_name': 'CKV_AZURE_71',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure that Managed identity provider is '
                                 'enabled for app services'},
    'CKV_AZURE_78': {   'categories': ['security'],
                        'description': 'Ensure FTP deployments are disabled',
                        'display_name': 'CKV_AZURE_78',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure FTP deployments are disabled'},
    'CKV_AZURE_8': {   'categories': ['security'],
                       'description': 'Ensure Kubernetes Dashboard is disabled',
                       'display_name': 'CKV_AZURE_8',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure Kubernetes Dashboard is disabled'},
    'CKV_AZURE_80': {   'categories': ['security'],
                        'description': "Ensure that 'Net Framework' version is "
                                       'the latest, if used as a part of the '
                                       'web app',
                        'display_name': 'CKV_AZURE_80',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': "Ensure that 'Net Framework' version is the "
                                 'latest, if used as a part of the web app'},
    'CKV_AZURE_88': {   'categories': ['security'],
                        'description': 'Ensure that app services use Azure '
                                       'Files',
                        'display_name': 'CKV_AZURE_88',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure that app services use Azure Files'},
    'CKV_AZURE_9': {   'categories': ['security'],
                       'description': 'Ensure that RDP access is restricted '
                                      'from the internet',
                       'display_name': 'CKV_AZURE_9',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Ensure that RDP access is restricted from the '
                                'internet'},
    'CKV_AZURE_93': {   'categories': ['security'],
                        'description': 'Ensure that managed disks use a '
                                       'specific set of disk encryption sets '
                                       'for the customer-managed key '
                                       'encryption',
                        'display_name': 'CKV_AZURE_93',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure that managed disks use a specific set '
                                 'of disk encryption sets for the '
                                 'customer-managed key encryption'},
    'CKV_AZURE_94': {   'categories': ['security'],
                        'description': 'Ensure that My SQL server enables '
                                       'geo-redundant backups',
                        'display_name': 'CKV_AZURE_94',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '1',
                        'title': 'Ensure that My SQL server enables '
                                 'geo-redundant backups'},
    'CKV_DOCKER_1': {   'categories': ['security'],
                        'description': 'Ensure port 22 is not exposed',
                        'display_name': 'Ensure port 22 is not exposed',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '3',
                        'title': 'Ensure port 22 is not exposed'},
    'CKV_DOCKER_10': {   'categories': ['security'],
                         'description': 'Ensure that WORKDIR values are '
                                        'absolute paths',
                         'display_name': 'Ensure that WORKDIR values are '
                                         'absolute paths',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '3',
                         'title': 'Ensure that WORKDIR values are absolute '
                                  'paths'},
    'CKV_DOCKER_11': {   'categories': ['security'],
                         'description': 'Ensure From Alias are unique for '
                                        'multistage builds.',
                         'display_name': 'Ensure From Alias are unique for '
                                         'multistage builds.',
                         'file': '%(issue.file)s',
                         'line': '%(issue.line)s',
                         'severity': '3',
                         'title': 'Ensure From Alias are unique for multistage '
                                  'builds.'},
    'CKV_DOCKER_2': {   'categories': ['security'],
                        'description': 'Ensure that HEALTHCHECK instructions '
                                       'have been added to container images',
                        'display_name': 'Ensure that HEALTHCHECK instructions '
                                        'have been added to container images',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '3',
                        'title': 'Ensure that HEALTHCHECK instructions have '
                                 'been added to container images'},
    'CKV_DOCKER_3': {   'categories': ['security'],
                        'description': 'Ensure that a user for the container '
                                       'has been created',
                        'display_name': 'Ensure that a user for the container '
                                        'has been created',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '3',
                        'title': 'Ensure that a user for the container has '
                                 'been created'},
    'CKV_DOCKER_4': {   'categories': ['security'],
                        'description': 'Ensure that COPY is used instead of '
                                       'ADD in Dockerfiles',
                        'display_name': 'Ensure that COPY is used instead of '
                                        'ADD in Dockerfiles',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '3',
                        'title': 'Ensure that COPY is used instead of ADD in '
                                 'Dockerfiles'},
    'CKV_DOCKER_5': {   'categories': ['security'],
                        'description': 'Ensure update instructions are not use '
                                       'alone in the Dockerfile',
                        'display_name': 'Ensure update instructions are not '
                                        'use alone in the Dockerfile',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '3',
                        'title': 'Ensure update instructions are not use alone '
                                 'in the Dockerfile'},
    'CKV_DOCKER_6': {   'categories': ['security'],
                        'description': 'Ensure that LABEL maintainer is used '
                                       'instead of MAINTAINER (deprecated)',
                        'display_name': 'Ensure that LABEL maintainer is used '
                                        'instead of MAINTAINER (deprecated)',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '3',
                        'title': 'Ensure that LABEL maintainer is used instead '
                                 'of MAINTAINER (deprecated)'},
    'CKV_DOCKER_7': {   'categories': ['security'],
                        'description': 'Ensure the base image uses a non '
                                       'latest version tag',
                        'display_name': 'Ensure the base image uses a non '
                                        'latest version tag',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '3',
                        'title': 'Ensure the base image uses a non latest '
                                 'version tag'},
    'CKV_DOCKER_8': {   'categories': ['security'],
                        'description': 'Ensure the last USER is not root',
                        'display_name': 'Ensure the last USER is not root',
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '3',
                        'title': 'Ensure the last USER is not root'},
    'CKV_DOCKER_9': {   'categories': ['security'],
                        'description': "Ensure that APT isn't used",
                        'display_name': "Ensure that APT isn't used",
                        'file': '%(issue.file)s',
                        'line': '%(issue.line)s',
                        'severity': '3',
                        'title': "Ensure that APT isn't used"},
    'CKV_GCP_1': {   'categories': ['security'],
                     'description': 'Ensure Stackdriver Logging is set to '
                                    'Enabled on Kubernetes Engine Clusters',
                     'display_name': 'CKV_GCP_1',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'Ensure Stackdriver Logging is set to Enabled on '
                              'Kubernetes Engine Clusters'},
    'CKV_GCP_10': {   'categories': ['security'],
                      'description': "Ensure 'Automatic node upgrade' is "
                                     'enabled for Kubernetes Clusters',
                      'display_name': 'CKV_GCP_10',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': "Ensure 'Automatic node upgrade' is enabled for "
                               'Kubernetes Clusters'},
    'CKV_GCP_11': {   'categories': ['security'],
                      'description': 'Ensure that Cloud SQL database Instances '
                                     'are not open to the world',
                      'display_name': 'CKV_GCP_11',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure that Cloud SQL database Instances are '
                               'not open to the world'},
    'CKV_GCP_12': {   'categories': ['security'],
                      'description': 'Ensure Network Policy is enabled on '
                                     'Kubernetes Engine Clusters',
                      'display_name': 'CKV_GCP_12',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure Network Policy is enabled on Kubernetes '
                               'Engine Clusters'},
    'CKV_GCP_13': {   'categories': ['security'],
                      'description': 'Ensure client certificate authentication '
                                     'to Kubernetes Engine Clusters is '
                                     'disabled',
                      'display_name': 'CKV_GCP_13',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure client certificate authentication to '
                               'Kubernetes Engine Clusters is disabled'},
    'CKV_GCP_14': {   'categories': ['security'],
                      'description': 'Ensure all Cloud SQL database instance '
                                     'have backup configuration enabled',
                      'display_name': 'CKV_GCP_14',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure all Cloud SQL database instance have '
                               'backup configuration enabled'},
    'CKV_GCP_15': {   'categories': ['security'],
                      'description': 'Ensure that BigQuery datasets are not '
                                     'anonymously or publicly accessible',
                      'display_name': 'CKV_GCP_15',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure that BigQuery datasets are not '
                               'anonymously or publicly accessible'},
    'CKV_GCP_18': {   'categories': ['security'],
                      'description': 'Ensure GKE Control Plane is not public',
                      'display_name': 'CKV_GCP_18',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure GKE Control Plane is not public'},
    'CKV_GCP_19': {   'categories': ['security'],
                      'description': 'Ensure GKE basic auth is disabled',
                      'display_name': 'CKV_GCP_19',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure GKE basic auth is disabled'},
    'CKV_GCP_2': {   'categories': ['security'],
                     'description': 'Ensure Google compute firewall ingress '
                                    'does not allow unrestricted ssh access',
                     'display_name': 'CKV_GCP_2',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'Ensure Google compute firewall ingress does not '
                              'allow unrestricted ssh access'},
    'CKV_GCP_21': {   'categories': ['security'],
                      'description': 'Ensure Kubernetes Clusters are '
                                     'configured with Labels',
                      'display_name': 'CKV_GCP_21',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure Kubernetes Clusters are configured with '
                               'Labels'},
    'CKV_GCP_22': {   'categories': ['security'],
                      'description': 'Ensure Container-Optimized OS (cos) is '
                                     'used for Kubernetes Engine Clusters Node '
                                     'image',
                      'display_name': 'CKV_GCP_22',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure Container-Optimized OS (cos) is used '
                               'for Kubernetes Engine Clusters Node image'},
    'CKV_GCP_23': {   'categories': ['security'],
                      'description': 'Ensure Kubernetes Cluster is created '
                                     'with Alias IP ranges enabled',
                      'display_name': 'CKV_GCP_23',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure Kubernetes Cluster is created with '
                               'Alias IP ranges enabled'},
    'CKV_GCP_24': {   'categories': ['security'],
                      'description': 'Ensure PodSecurityPolicy controller is '
                                     'enabled on the Kubernetes Engine '
                                     'Clusters',
                      'display_name': 'CKV_GCP_24',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure PodSecurityPolicy controller is enabled '
                               'on the Kubernetes Engine Clusters'},
    'CKV_GCP_25': {   'categories': ['security'],
                      'description': 'Ensure Kubernetes Cluster is created '
                                     'with Private cluster enabled',
                      'display_name': 'CKV_GCP_25',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure Kubernetes Cluster is created with '
                               'Private cluster enabled'},
    'CKV_GCP_26': {   'categories': ['security'],
                      'description': 'Ensure that VPC Flow Logs is enabled for '
                                     'every subnet in a VPC Network',
                      'display_name': 'CKV_GCP_26',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure that VPC Flow Logs is enabled for every '
                               'subnet in a VPC Network'},
    'CKV_GCP_28': {   'categories': ['security'],
                      'description': 'Ensure that Cloud Storage bucket is not '
                                     'anonymously or publicly accessible',
                      'display_name': 'CKV_GCP_28',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure that Cloud Storage bucket is not '
                               'anonymously or publicly accessible'},
    'CKV_GCP_29': {   'categories': ['security'],
                      'description': 'Ensure that Cloud Storage buckets have '
                                     'uniform bucket-level access enabled',
                      'display_name': 'CKV_GCP_29',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure that Cloud Storage buckets have uniform '
                               'bucket-level access enabled'},
    'CKV_GCP_3': {   'categories': ['security'],
                     'description': 'Ensure Google compute firewall ingress '
                                    'does not allow unrestricted rdp access',
                     'display_name': 'CKV_GCP_3',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'Ensure Google compute firewall ingress does not '
                              'allow unrestricted rdp access'},
    'CKV_GCP_30': {   'categories': ['security'],
                      'description': 'Ensure that instances are not configured '
                                     'to use the default service account',
                      'display_name': 'CKV_GCP_30',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure that instances are not configured to '
                               'use the default service account'},
    'CKV_GCP_32': {   'categories': ['security'],
                      'description': "Ensure 'Block Project-wide SSH keys' is "
                                     'enabled for VM instances',
                      'display_name': 'CKV_GCP_32',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': "Ensure 'Block Project-wide SSH keys' is "
                               'enabled for VM instances'},
    'CKV_GCP_34': {   'categories': ['security'],
                      'description': 'Ensure that no instance in the project '
                                     'overrides the project setting for '
                                     'enabling OSLogin(OSLogin needs to be '
                                     'enabled in project metadata for all '
                                     'instances)',
                      'display_name': 'CKV_GCP_34',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure that no instance in the project '
                               'overrides the project setting for enabling '
                               'OSLogin(OSLogin needs to be enabled in project '
                               'metadata for all instances)'},
    'CKV_GCP_35': {   'categories': ['security'],
                      'description': "Ensure 'Enable connecting to serial "
                                     "ports' is not enabled for VM Instance",
                      'display_name': 'CKV_GCP_35',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': "Ensure 'Enable connecting to serial ports' is "
                               'not enabled for VM Instance'},
    'CKV_GCP_36': {   'categories': ['security'],
                      'description': 'Ensure that IP forwarding is not enabled '
                                     'on Instances',
                      'display_name': 'CKV_GCP_36',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure that IP forwarding is not enabled on '
                               'Instances'},
    'CKV_GCP_37': {   'categories': ['security'],
                      'description': 'Ensure VM disks for critical VMs are '
                                     'encrypted with Customer Supplied '
                                     'Encryption Keys (CSEK)',
                      'display_name': 'CKV_GCP_37',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure VM disks for critical VMs are encrypted '
                               'with Customer Supplied Encryption Keys (CSEK)'},
    'CKV_GCP_38': {   'categories': ['security'],
                      'description': 'Ensure VM disks for critical VMs are '
                                     'encrypted with Customer Supplied '
                                     'Encryption Keys (CSEK)',
                      'display_name': 'CKV_GCP_38',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure VM disks for critical VMs are encrypted '
                               'with Customer Supplied Encryption Keys (CSEK)'},
    'CKV_GCP_39': {   'categories': ['security'],
                      'description': 'Ensure Compute instances are launched '
                                     'with Shielded VM enabled',
                      'display_name': 'CKV_GCP_39',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure Compute instances are launched with '
                               'Shielded VM enabled'},
    'CKV_GCP_40': {   'categories': ['security'],
                      'description': 'Ensure that Compute instances do not '
                                     'have public IP addresses',
                      'display_name': 'CKV_GCP_40',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure that Compute instances do not have '
                               'public IP addresses'},
    'CKV_GCP_6': {   'categories': ['security'],
                     'description': 'Ensure all Cloud SQL database instance '
                                    'requires all incoming connections to use '
                                    'SSL',
                     'display_name': 'CKV_GCP_6',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'Ensure all Cloud SQL database instance requires '
                              'all incoming connections to use SSL'},
    'CKV_GCP_60': {   'categories': ['security'],
                      'description': 'Ensure Cloud SQL database does not have '
                                     'public IP',
                      'display_name': 'CKV_GCP_60',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure Cloud SQL database does not have public '
                               'IP'},
    'CKV_GCP_61': {   'categories': ['security'],
                      'description': 'Enable VPC Flow Logs and Intranode '
                                     'Visibility',
                      'display_name': 'CKV_GCP_61',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Enable VPC Flow Logs and Intranode Visibility'},
    'CKV_GCP_62': {   'categories': ['security'],
                      'description': 'Bucket should log access',
                      'display_name': 'CKV_GCP_62',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Bucket should log access'},
    'CKV_GCP_64': {   'categories': ['security'],
                      'description': 'Ensure clusters are created with Private '
                                     'Nodes',
                      'display_name': 'CKV_GCP_64',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure clusters are created with Private '
                               'Nodes'},
    'CKV_GCP_65': {   'categories': ['security'],
                      'description': 'Manage Kubernetes RBAC users with Google '
                                     'Groups for GKE',
                      'display_name': 'CKV_GCP_65',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Manage Kubernetes RBAC users with Google '
                               'Groups for GKE'},
    'CKV_GCP_66': {   'categories': ['security'],
                      'description': 'Ensure use of Binary Authorization',
                      'display_name': 'CKV_GCP_66',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure use of Binary Authorization'},
    'CKV_GCP_67': {   'categories': ['security'],
                      'description': 'Ensure legacy Compute Engine instance '
                                     'metadata APIs are Disabled',
                      'display_name': 'CKV_GCP_67',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure legacy Compute Engine instance metadata '
                               'APIs are Disabled'},
    'CKV_GCP_68': {   'categories': ['security'],
                      'description': 'Ensure Secure Boot for Shielded GKE '
                                     'Nodes is Enabled',
                      'display_name': 'CKV_GCP_68',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure Secure Boot for Shielded GKE Nodes is '
                               'Enabled'},
    'CKV_GCP_69': {   'categories': ['security'],
                      'description': 'Ensure the GKE Metadata Server is '
                                     'Enabled',
                      'display_name': 'CKV_GCP_69',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure the GKE Metadata Server is Enabled'},
    'CKV_GCP_7': {   'categories': ['security'],
                     'description': 'Ensure Legacy Authorization is set to '
                                    'Disabled on Kubernetes Engine Clusters',
                     'display_name': 'CKV_GCP_7',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'Ensure Legacy Authorization is set to Disabled '
                              'on Kubernetes Engine Clusters'},
    'CKV_GCP_70': {   'categories': ['security'],
                      'description': 'Ensure the GKE Release Channel is set',
                      'display_name': 'CKV_GCP_70',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure the GKE Release Channel is set'},
    'CKV_GCP_74': {   'categories': ['security'],
                      'description': 'Ensure that private_ip_google_access is '
                                     'enabled for Subnet',
                      'display_name': 'CKV_GCP_74',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure that private_ip_google_access is '
                               'enabled for Subnet'},
    'CKV_GCP_75': {   'categories': ['security'],
                      'description': 'Ensure Google compute firewall ingress '
                                     'does not allow unrestricted FTP access',
                      'display_name': 'CKV_GCP_75',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure Google compute firewall ingress does '
                               'not allow unrestricted FTP access'},
    'CKV_GCP_76': {   'categories': ['security'],
                      'description': 'Ensure that Private google access is '
                                     'enabled for IPV6',
                      'display_name': 'CKV_GCP_76',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure that Private google access is enabled '
                               'for IPV6'},
    'CKV_GCP_77': {   'categories': ['security'],
                      'description': 'Ensure Google compute firewall ingress '
                                     'does not allow on ftp port',
                      'display_name': 'CKV_GCP_77',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure Google compute firewall ingress does '
                               'not allow on ftp port'},
    'CKV_GCP_78': {   'categories': ['security'],
                      'description': 'Ensure Cloud storage has versioning '
                                     'enabled',
                      'display_name': 'CKV_GCP_78',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure Cloud storage has versioning enabled'},
    'CKV_GCP_79': {   'categories': ['security'],
                      'description': 'Ensure SQL database is using latest '
                                     'Major version',
                      'display_name': 'CKV_GCP_79',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure SQL database is using latest Major '
                               'version'},
    'CKV_GCP_8': {   'categories': ['security'],
                     'description': 'Ensure Stackdriver Monitoring is set to '
                                    'Enabled on Kubernetes Engine Clusters',
                     'display_name': 'CKV_GCP_8',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'Ensure Stackdriver Monitoring is set to Enabled '
                              'on Kubernetes Engine Clusters'},
    'CKV_GCP_81': {   'categories': ['security'],
                      'description': 'Ensure Big Query Tables are encrypted '
                                     'with Customer Supplied Encryption Keys '
                                     '(CSEK)',
                      'display_name': 'CKV_GCP_81',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure Big Query Tables are encrypted with '
                               'Customer Supplied Encryption Keys (CSEK)'},
    'CKV_GCP_88': {   'categories': ['security'],
                      'description': 'Ensure Google compute firewall ingress '
                                     'does not allow unrestricted mysql access',
                      'display_name': 'CKV_GCP_88',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure Google compute firewall ingress does '
                               'not allow unrestricted mysql access'},
    'CKV_GCP_9': {   'categories': ['security'],
                     'description': "Ensure 'Automatic node repair' is enabled "
                                    'for Kubernetes Clusters',
                     'display_name': 'CKV_GCP_9',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': "Ensure 'Automatic node repair' is enabled for "
                              'Kubernetes Clusters'},
    'CKV_K8S_10': {   'categories': ['security'],
                      'description': 'CPU requests should be set',
                      'display_name': 'CKV_K8S_10',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'CPU requests should be set'},
    'CKV_K8S_11': {   'categories': ['security'],
                      'description': 'CPU limits should be set',
                      'display_name': 'CKV_K8S_11',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'CPU limits should be set'},
    'CKV_K8S_12': {   'categories': ['security'],
                      'description': 'Memory requests should be set',
                      'display_name': 'CKV_K8S_12',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Memory requests should be set'},
    'CKV_K8S_13': {   'categories': ['security'],
                      'description': 'Memory limits should be set',
                      'display_name': 'CKV_K8S_13',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Memory limits should be set'},
    'CKV_K8S_14': {   'categories': ['security'],
                      'description': 'Image Tag should be fixed - not latest '
                                     'or blank',
                      'display_name': 'CKV_K8S_14',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Image Tag should be fixed - not latest or '
                               'blank'},
    'CKV_K8S_155': {   'categories': ['security'],
                       'description': 'Minimize ClusterRoles that grant '
                                      'control over validating or mutating '
                                      'admission webhook configurations',
                       'display_name': 'CKV_K8S_155',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Minimize ClusterRoles that grant control over '
                                'validating or mutating admission webhook '
                                'configurations'},
    'CKV_K8S_156': {   'categories': ['security'],
                       'description': 'Minimize ClusterRoles that grant '
                                      'permissions to approve '
                                      'CertificateSigningRequests',
                       'display_name': 'CKV_K8S_156',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Minimize ClusterRoles that grant permissions '
                                'to approve CertificateSigningRequests'},
    'CKV_K8S_157': {   'categories': ['security'],
                       'description': 'Minimize Roles and ClusterRoles that '
                                      'grant permissions to bind RoleBindings '
                                      'or ClusterRoleBindings',
                       'display_name': 'CKV_K8S_157',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Minimize Roles and ClusterRoles that grant '
                                'permissions to bind RoleBindings or '
                                'ClusterRoleBindings'},
    'CKV_K8S_158': {   'categories': ['security'],
                       'description': 'Minimize Roles and ClusterRoles that '
                                      'grant permissions to escalate Roles or '
                                      'ClusterRoles',
                       'display_name': 'CKV_K8S_158',
                       'file': '%(issue.file)s',
                       'line': '%(issue.line)s',
                       'severity': '1',
                       'title': 'Minimize Roles and ClusterRoles that grant '
                                'permissions to escalate Roles or '
                                'ClusterRoles'},
    'CKV_K8S_16': {   'categories': ['security'],
                      'description': 'Container should not be privileged',
                      'display_name': 'CKV_K8S_16',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Container should not be privileged'},
    'CKV_K8S_17': {   'categories': ['security'],
                      'description': 'Containers should not share the host '
                                     'process ID namespace',
                      'display_name': 'CKV_K8S_17',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Containers should not share the host process '
                               'ID namespace'},
    'CKV_K8S_18': {   'categories': ['security'],
                      'description': 'Containers should not share the host IPC '
                                     'namespace',
                      'display_name': 'CKV_K8S_18',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Containers should not share the host IPC '
                               'namespace'},
    'CKV_K8S_19': {   'categories': ['security'],
                      'description': 'Containers should not share the host '
                                     'network namespace',
                      'display_name': 'CKV_K8S_19',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Containers should not share the host network '
                               'namespace'},
    'CKV_K8S_20': {   'categories': ['security'],
                      'description': 'Containers should not run with '
                                     'allowPrivilegeEscalation',
                      'display_name': 'CKV_K8S_20',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Containers should not run with '
                               'allowPrivilegeEscalation'},
    'CKV_K8S_21': {   'categories': ['security'],
                      'description': 'The default namespace should not be used',
                      'display_name': 'CKV_K8S_21',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'The default namespace should not be used'},
    'CKV_K8S_22': {   'categories': ['security'],
                      'description': 'Use read-only filesystem for containers '
                                     'where possible',
                      'display_name': 'CKV_K8S_22',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Use read-only filesystem for containers where '
                               'possible'},
    'CKV_K8S_23': {   'categories': ['security'],
                      'description': 'Minimize the admission of root '
                                     'containers',
                      'display_name': 'CKV_K8S_23',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Minimize the admission of root containers'},
    'CKV_K8S_25': {   'categories': ['security'],
                      'description': 'Minimize the admission of containers '
                                     'with added capability',
                      'display_name': 'CKV_K8S_25',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Minimize the admission of containers with '
                               'added capability'},
    'CKV_K8S_27': {   'categories': ['security'],
                      'description': 'Do not expose the docker daemon socket '
                                     'to containers',
                      'display_name': 'CKV_K8S_27',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Do not expose the docker daemon socket to '
                               'containers'},
    'CKV_K8S_28': {   'categories': ['security'],
                      'description': 'Minimize the admission of containers '
                                     'with the NET_RAW capability',
                      'display_name': 'CKV_K8S_28',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Minimize the admission of containers with the '
                               'NET_RAW capability'},
    'CKV_K8S_29': {   'categories': ['security'],
                      'description': 'Apply security context to your pods and '
                                     'containers',
                      'display_name': 'CKV_K8S_29',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Apply security context to your pods and '
                               'containers'},
    'CKV_K8S_30': {   'categories': ['security'],
                      'description': 'Apply security context to your pods and '
                                     'containers',
                      'display_name': 'CKV_K8S_30',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Apply security context to your pods and '
                               'containers'},
    'CKV_K8S_31': {   'categories': ['security'],
                      'description': 'Ensure that the seccomp profile is set '
                                     'to docker/default or runtime/default',
                      'display_name': 'CKV_K8S_31',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure that the seccomp profile is set to '
                               'docker/default or runtime/default'},
    'CKV_K8S_35': {   'categories': ['security'],
                      'description': 'Prefer using secrets as files over '
                                     'secrets as environment variables',
                      'display_name': 'CKV_K8S_35',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Prefer using secrets as files over secrets as '
                               'environment variables'},
    'CKV_K8S_37': {   'categories': ['security'],
                      'description': 'Minimize the admission of containers '
                                     'with capabilities assigned',
                      'display_name': 'CKV_K8S_37',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Minimize the admission of containers with '
                               'capabilities assigned'},
    'CKV_K8S_38': {   'categories': ['security'],
                      'description': 'Ensure that Service Account Tokens are '
                                     'only mounted where necessary',
                      'display_name': 'CKV_K8S_38',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure that Service Account Tokens are only '
                               'mounted where necessary'},
    'CKV_K8S_40': {   'categories': ['security'],
                      'description': 'Containers should run as a high UID to '
                                     'avoid host conflict',
                      'display_name': 'CKV_K8S_40',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Containers should run as a high UID to avoid '
                               'host conflict'},
    'CKV_K8S_43': {   'categories': ['security'],
                      'description': 'Image should use digest',
                      'display_name': 'CKV_K8S_43',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Image should use digest'},
    'CKV_K8S_49': {   'categories': ['security'],
                      'description': 'Minimize wildcard use in Roles and '
                                     'ClusterRoles',
                      'display_name': 'CKV_K8S_49',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Minimize wildcard use in Roles and '
                               'ClusterRoles'},
    'CKV_K8S_8': {   'categories': ['security'],
                     'description': 'Liveness Probe Should be Configured',
                     'display_name': 'CKV_K8S_8',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'Liveness Probe Should be Configured'},
    'CKV_K8S_9': {   'categories': ['security'],
                     'description': 'Readiness Probe Should be Configured',
                     'display_name': 'CKV_K8S_9',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'Readiness Probe Should be Configured'},
    'CKV_OCI_10': {   'categories': ['security'],
                      'description': 'Ensure OCI Object Storage is not Public',
                      'display_name': 'CKV_OCI_10',
                      'file': '%(issue.file)s',
                      'line': '%(issue.line)s',
                      'severity': '1',
                      'title': 'Ensure OCI Object Storage is not Public'},
    'CKV_OCI_7': {   'categories': ['security'],
                     'description': 'Ensure OCI Object Storage bucket can emit '
                                    'object events',
                     'display_name': 'CKV_OCI_7',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'Ensure OCI Object Storage bucket can emit '
                              'object events'},
    'CKV_OCI_8': {   'categories': ['security'],
                     'description': 'Ensure OCI Object Storage has versioning '
                                    'enabled',
                     'display_name': 'CKV_OCI_8',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'Ensure OCI Object Storage has versioning '
                              'enabled'},
    'CKV_OCI_9': {   'categories': ['security'],
                     'description': 'Ensure OCI Object Storage is encrypted '
                                    'with Customer Managed Key',
                     'display_name': 'CKV_OCI_9',
                     'file': '%(issue.file)s',
                     'line': '%(issue.line)s',
                     'severity': '1',
                     'title': 'Ensure OCI Object Storage is encrypted with '
                              'Customer Managed Key'}}

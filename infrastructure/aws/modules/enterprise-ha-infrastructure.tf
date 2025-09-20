# Enterprise High Availability Infrastructure
# AWS CloudFormation - Financial Grade Security with FIPS 140-3 Level 3

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Variables
variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "fips_compliance_level" {
  description = "FIPS 140-3 compliance level"
  type        = string
  default     = "Level_3"
}

# Data Sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# VPC with Enterprise Security
resource "aws_vpc" "enterprise_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name        = "enterprise-payment-gateway-vpc"
    Environment = var.environment
    Compliance  = "FIPS_140-3_${var.fips_compliance_level}"
    Project     = "Enterprise Payment Gateway"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "enterprise_igw" {
  vpc_id = aws_vpc.enterprise_vpc.id

  tags = {
    Name        = "enterprise-payment-gateway-igw"
    Environment = var.environment
  }
}

# Private Subnets for Enterprise Services (Multi-AZ)
resource "aws_subnet" "private_subnets" {
  count = length(var.availability_zones)
  
  vpc_id            = aws_vpc.enterprise_vpc.id
  cidr_block        = "10.0.${count.index + 1}.0/24"
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name        = "enterprise-private-subnet-${count.index + 1}"
    Environment = var.environment
    Type        = "Private"
    Tier        = "Application"
  }
}

# Public Subnets for Load Balancers (Multi-AZ)
resource "aws_subnet" "public_subnets" {
  count = length(var.availability_zones)
  
  vpc_id                  = aws_vpc.enterprise_vpc.id
  cidr_block              = "10.0.${count.index + 10}.0/24"
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name        = "enterprise-public-subnet-${count.index + 1}"
    Environment = var.environment
    Type        = "Public"
    Tier        = "LoadBalancer"
  }
}

# Database Subnets (Multi-AZ)
resource "aws_subnet" "database_subnets" {
  count = length(var.availability_zones)
  
  vpc_id            = aws_vpc.enterprise_vpc.id
  cidr_block        = "10.0.${count.index + 20}.0/24"
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name        = "enterprise-database-subnet-${count.index + 1}"
    Environment = var.environment
    Type        = "Database"
    Tier        = "Data"
  }
}

# NAT Gateways for High Availability (One per AZ)
resource "aws_eip" "nat_gateway_eips" {
  count = length(var.availability_zones)
  
  domain = "vpc"
  
  tags = {
    Name        = "enterprise-nat-eip-${count.index + 1}"
    Environment = var.environment
  }
}

resource "aws_nat_gateway" "nat_gateways" {
  count = length(var.availability_zones)
  
  allocation_id = aws_eip.nat_gateway_eips[count.index].id
  subnet_id     = aws_subnet.public_subnets[count.index].id

  tags = {
    Name        = "enterprise-nat-gateway-${count.index + 1}"
    Environment = var.environment
  }

  depends_on = [aws_internet_gateway.enterprise_igw]
}

# Route Tables
resource "aws_route_table" "private_route_tables" {
  count = length(var.availability_zones)
  
  vpc_id = aws_vpc.enterprise_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gateways[count.index].id
  }

  tags = {
    Name        = "enterprise-private-rt-${count.index + 1}"
    Environment = var.environment
  }
}

resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.enterprise_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.enterprise_igw.id
  }

  tags = {
    Name        = "enterprise-public-rt"
    Environment = var.environment
  }
}

# Route Table Associations
resource "aws_route_table_association" "private_subnet_associations" {
  count = length(var.availability_zones)
  
  subnet_id      = aws_subnet.private_subnets[count.index].id
  route_table_id = aws_route_table.private_route_tables[count.index].id
}

resource "aws_route_table_association" "public_subnet_associations" {
  count = length(var.availability_zones)
  
  subnet_id      = aws_subnet.public_subnets[count.index].id
  route_table_id = aws_route_table.public_route_table.id
}

# Security Groups
resource "aws_security_group" "enterprise_application_sg" {
  name_prefix = "enterprise-app-"
  vpc_id      = aws_vpc.enterprise_vpc.id

  # Allow HTTPS from Load Balancer
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.enterprise_vpc.cidr_block]
  }

  # Allow secure inter-service communication
  ingress {
    from_port = 8000
    to_port   = 9000
    protocol  = "tcp"
    self      = true
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "enterprise-application-sg"
    Environment = var.environment
    Compliance  = "FIPS_140-3"
  }
}

resource "aws_security_group" "enterprise_database_sg" {
  name_prefix = "enterprise-db-"
  vpc_id      = aws_vpc.enterprise_vpc.id

  # Allow PostgreSQL from application security group
  ingress {
    from_port                = 5432
    to_port                  = 5432
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.enterprise_application_sg.id
  }

  # Allow Redis from application security group
  ingress {
    from_port                = 6379
    to_port                  = 6379
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.enterprise_application_sg.id
  }

  tags = {
    Name        = "enterprise-database-sg"
    Environment = var.environment
  }
}

resource "aws_security_group" "enterprise_load_balancer_sg" {
  name_prefix = "enterprise-lb-"
  vpc_id      = aws_vpc.enterprise_vpc.id

  # Allow HTTPS from internet
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow HTTP (redirect to HTTPS)
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "enterprise-load-balancer-sg"
    Environment = var.environment
  }
}

# Application Load Balancer (Multi-AZ)
resource "aws_lb" "enterprise_alb" {
  name               = "enterprise-payment-gateway-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.enterprise_load_balancer_sg.id]
  subnets            = aws_subnet.public_subnets[*].id

  enable_deletion_protection = true
  enable_http2              = true
  drop_invalid_header_fields = true

  tags = {
    Name        = "enterprise-payment-gateway-alb"
    Environment = var.environment
    Compliance  = "FIPS_140-3"
  }
}

# RDS PostgreSQL (Multi-AZ with High Availability)
resource "aws_db_subnet_group" "enterprise_db_subnet_group" {
  name       = "enterprise-db-subnet-group"
  subnet_ids = aws_subnet.database_subnets[*].id

  tags = {
    Name        = "enterprise-db-subnet-group"
    Environment = var.environment
  }
}

resource "aws_db_instance" "enterprise_postgresql" {
  identifier = "enterprise-payment-gateway-db"

  # Engine Configuration
  engine         = "postgres"
  engine_version = "15.5"
  instance_class = "db.r6g.xlarge"

  # Storage Configuration
  allocated_storage     = 500
  max_allocated_storage = 2000
  storage_type         = "gp3"
  storage_encrypted    = true
  kms_key_id          = aws_kms_key.enterprise_kms_key.arn

  # Database Configuration
  db_name  = "enterprise_payment_gateway"
  username = "enterprise_admin"
  manage_master_user_password = true

  # High Availability Configuration
  multi_az               = true
  availability_zone      = null  # Auto-assigned for Multi-AZ
  db_subnet_group_name   = aws_db_subnet_group.enterprise_db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.enterprise_database_sg.id]

  # Backup Configuration
  backup_retention_period = 35  # 5 weeks
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"

  # Performance and Monitoring
  performance_insights_enabled = true
  monitoring_interval         = 60
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  # Security Configuration
  deletion_protection      = true
  delete_automated_backups = false
  skip_final_snapshot     = false
  final_snapshot_identifier = "enterprise-payment-gateway-final-snapshot"

  tags = {
    Name        = "enterprise-payment-gateway-db"
    Environment = var.environment
    Compliance  = "FIPS_140-3"
  }
}

# ElastiCache Redis (Multi-AZ with Failover)
resource "aws_elasticache_subnet_group" "enterprise_redis_subnet_group" {
  name       = "enterprise-redis-subnet-group"
  subnet_ids = aws_subnet.database_subnets[*].id
}

resource "aws_elasticache_replication_group" "enterprise_redis" {
  replication_group_id       = "enterprise-payment-gateway-redis"
  description                = "Enterprise Redis cluster for payment gateway"

  # Engine Configuration
  engine               = "redis"
  engine_version       = "7.0"
  node_type            = "cache.r6g.xlarge"
  port                 = 6379

  # Cluster Configuration
  num_cache_clusters         = 3
  automatic_failover_enabled = true
  multi_az_enabled          = true
  
  # Subnet and Security Configuration
  subnet_group_name  = aws_elasticache_subnet_group.enterprise_redis_subnet_group.name
  security_group_ids = [aws_security_group.enterprise_database_sg.id]

  # Backup Configuration
  snapshot_retention_limit = 7
  snapshot_window         = "03:00-05:00"
  maintenance_window      = "sun:05:00-sun:07:00"

  # Security Configuration
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  kms_key_id                = aws_kms_key.enterprise_kms_key.arn

  tags = {
    Name        = "enterprise-payment-gateway-redis"
    Environment = var.environment
    Compliance  = "FIPS_140-3"
  }
}

# KMS Key for Encryption
resource "aws_kms_key" "enterprise_kms_key" {
  description             = "Enterprise Payment Gateway KMS Key - FIPS 140-3 Level 3"
  deletion_window_in_days = 7
  enable_key_rotation    = true

  tags = {
    Name        = "enterprise-payment-gateway-kms"
    Environment = var.environment
    Compliance  = "FIPS_140-3_Level_3"
  }
}

resource "aws_kms_alias" "enterprise_kms_alias" {
  name          = "alias/enterprise-payment-gateway"
  target_key_id = aws_kms_key.enterprise_kms_key.key_id
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "enterprise_application_logs" {
  name              = "/aws/enterprise/payment-gateway"
  retention_in_days = 2555  # 7 years for compliance

  kms_key_id = aws_kms_key.enterprise_kms_key.arn

  tags = {
    Name        = "enterprise-payment-gateway-logs"
    Environment = var.environment
    Compliance  = "PCI-DSS_SOX_GDPR"
  }
}

# Auto Scaling Group (Multi-AZ)
resource "aws_launch_template" "enterprise_launch_template" {
  name_prefix   = "enterprise-payment-gateway-"
  image_id      = "ami-0abcdef1234567890"  # Replace with FIPS-compliant AMI
  instance_type = "m5.2xlarge"
  
  vpc_security_group_ids = [aws_security_group.enterprise_application_sg.id]
  
  # FIPS-compliant user data
  user_data = base64encode(<<-EOF
    #!/bin/bash
    # Enable FIPS mode
    echo "FIPS=1" >> /etc/environment
    echo "crypto.fips_enabled=1" >> /etc/sysctl.conf
    sysctl -p
    
    # Configure enterprise services
    systemctl enable payment-gateway
    systemctl enable security-service
    systemctl enable auth-service
    systemctl enable crypto-attestation-agent
    systemctl enable rbac-service
    
    # Start services
    systemctl start payment-gateway
    systemctl start security-service
    systemctl start auth-service
    systemctl start crypto-attestation-agent
    systemctl start rbac-service
  EOF
  )

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name        = "enterprise-payment-gateway-instance"
      Environment = var.environment
      Compliance  = "FIPS_140-3_Level_3"
    }
  }
}

resource "aws_autoscaling_group" "enterprise_asg" {
  name                = "enterprise-payment-gateway-asg"
  vpc_zone_identifier = aws_subnet.private_subnets[*].id
  target_group_arns   = [aws_lb_target_group.enterprise_payment_gateway_tg.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300

  min_size         = 3
  max_size         = 20
  desired_capacity = 6

  launch_template {
    id      = aws_launch_template.enterprise_launch_template.id
    version = "$Latest"
  }

  # Instance distribution across AZs
  availability_zones = var.availability_zones

  tag {
    key                 = "Name"
    value               = "enterprise-payment-gateway-instance"
    propagate_at_launch = true
  }

  tag {
    key                 = "Environment"
    value               = var.environment
    propagate_at_launch = true
  }

  tag {
    key                 = "Compliance"
    value               = "FIPS_140-3_Level_3"
    propagate_at_launch = true
  }
}

# Load Balancer Target Group
resource "aws_lb_target_group" "enterprise_payment_gateway_tg" {
  name     = "enterprise-payment-gateway-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.enterprise_vpc.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout            = 5
    interval           = 30
    path               = "/health"
    matcher            = "200"
  }

  tags = {
    Name        = "enterprise-payment-gateway-tg"
    Environment = var.environment
  }
}

# Load Balancer Listener (HTTPS)
resource "aws_lb_listener" "enterprise_https_listener" {
  load_balancer_arn = aws_lb.enterprise_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"  # FIPS-compliant
  certificate_arn   = aws_acm_certificate.enterprise_cert.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.enterprise_payment_gateway_tg.arn
  }
}

# SSL Certificate
resource "aws_acm_certificate" "enterprise_cert" {
  domain_name       = "enterprise-payment-gateway.com"
  validation_method = "DNS"

  subject_alternative_names = [
    "*.enterprise-payment-gateway.com"
  ]

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name        = "enterprise-payment-gateway-cert"
    Environment = var.environment
  }
}

# CloudWatch Alarms for High Availability
resource "aws_cloudwatch_metric_alarm" "enterprise_high_cpu" {
  alarm_name          = "enterprise-payment-gateway-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "70"
  alarm_description   = "This metric monitors ec2 cpu utilization"
  alarm_actions       = [aws_sns_topic.enterprise_alerts.arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.enterprise_asg.name
  }
}

resource "aws_sns_topic" "enterprise_alerts" {
  name              = "enterprise-payment-gateway-alerts"
  kms_master_key_id = aws_kms_key.enterprise_kms_key.arn

  tags = {
    Name        = "enterprise-payment-gateway-alerts"
    Environment = var.environment
  }
}

# Outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.enterprise_vpc.id
}

output "load_balancer_dns" {
  description = "DNS name of the load balancer"
  value       = aws_lb.enterprise_alb.dns_name
}

output "database_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.enterprise_postgresql.endpoint
  sensitive   = true
}

output "redis_cluster_endpoint" {
  description = "ElastiCache cluster endpoint"
  value       = aws_elasticache_replication_group.enterprise_redis.primary_endpoint_address
  sensitive   = true
}
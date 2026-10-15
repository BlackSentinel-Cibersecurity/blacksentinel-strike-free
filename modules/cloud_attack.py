#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
        CLOUD ATTACK MODULE - BlackSentinel Strike v4.0
═══════════════════════════════════════════════════════════════
Copyright (c) 2024-2025 BlackSentinel Strike - All Rights Reserved
"""

import subprocess
import json
import threading


class CloudAttack:
    """Advanced Cloud Attack Module for AWS, Azure, and GCP penetration testing."""

    def __init__(self, callback=None):
        self.callback = callback
        self.results = {}
        self.is_running = False
        self._lock = threading.Lock()

    def log(self, message, level="info"):
        if self.callback:
            self.callback(message, level)

    def run_command(self, cmd, timeout=30):
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            self.log(f"Command timed out after {timeout}s", "warning")
            return None
        except Exception as e:
            self.log(f"Command failed: {e}", "error")
            return None

    # ══════════════════════════════════════════════════════════
    #  AWS ATTACKS (20 methods)
    # ══════════════════════════════════════════════════════════

    def aws_enum_users(self, target):
        """Enumerate IAM users via AWS CLI."""
        self.log(f"[AWS] Enumerating IAM users on {target}", "info")
        try:
            output = self.run_command("aws iam list-users --output json", timeout=60)
            if output:
                users = json.loads(output).get("Users", [])
                result_lines = []
                for u in users:
                    result_lines.append(
                        f"User: {u['UserName']} | Arn: {u['Arn']} | Created: {u['CreateDate']}"
                    )
                self.log(f"[AWS] Found {len(users)} IAM users", "success")
                return "\n".join(result_lines) if result_lines else "No IAM users found"
            return "No output from AWS CLI"
        except Exception as e:
            return f"AWS user enum failed: {e}"

    def aws_enum_roles(self, target):
        """Enumerate IAM roles."""
        self.log(f"[AWS] Enumerating IAM roles on {target}", "info")
        try:
            output = self.run_command("aws iam list-roles --output json", timeout=60)
            if output:
                roles = json.loads(output).get("Roles", [])
                result_lines = []
                for r in roles:
                    result_lines.append(
                        f"Role: {r['RoleName']} | Arn: {r['Arn']} | Path: {r.get('Path', '/')}"
                    )
                self.log(f"[AWS] Found {len(roles)} IAM roles", "success")
                return "\n".join(result_lines) if result_lines else "No IAM roles found"
            return "No output from AWS CLI"
        except Exception as e:
            return f"AWS role enum failed: {e}"

    def aws_enum_policies(self, target):
        """Enumerate IAM policies including attached and unattached."""
        self.log(f"[AWS] Enumerating IAM policies on {target}", "info")
        try:
            output = self.run_command("aws iam list-policies --scope Local --output json", timeout=60)
            if output:
                policies = json.loads(output).get("Policies", [])
                result_lines = []
                for p in policies:
                    result_lines.append(
                        f"Policy: {p['PolicyName']} | Arn: {p['Arn']} | Version: {p['DefaultVersionId']}"
                    )
                self.log(f"[AWS] Found {len(policies)} policies", "success")
                return "\n".join(result_lines) if result_lines else "No policies found"
            return "No output"
        except Exception as e:
            return f"AWS policy enum failed: {e}"

    def aws_enum_s3_buckets(self, target):
        """Enumerate S3 buckets accessible with current credentials."""
        self.log(f"[AWS] Enumerating S3 buckets on {target}", "info")
        try:
            output = self.run_command("aws s3api list-buckets --output json", timeout=60)
            if output:
                buckets = json.loads(output).get("Buckets", [])
                result_lines = []
                for b in buckets:
                    result_lines.append(
                        f"Bucket: {b['Name']} | Created: {b['CreationDate']}"
                    )
                self.log(f"[AWS] Found {len(buckets)} S3 buckets", "success")
                return "\n".join(result_lines) if result_lines else "No S3 buckets found"
            return "No output"
        except Exception as e:
            return f"AWS S3 enum failed: {e}"

    def aws_enum_ec2_instances(self, target):
        """Enumerate EC2 instances across regions."""
        self.log(f"[AWS] Enumerating EC2 instances on {target}", "info")
        try:
            output = self.run_command(
                "aws ec2 describe-instances --output json", timeout=60
            )
            if output:
                data = json.loads(output)
                instances = []
                for reservation in data.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        name = next(
                            (t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"),
                            "N/A",
                        )
                        instances.append(
                            f"ID: {inst['InstanceId']} | State: {inst['State']['Name']} "
                            f"| Type: {inst['InstanceType']} | Name: {name} "
                            f"| PrivateIP: {inst.get('PrivateIpAddress', 'N/A')}"
                        )
                self.log(f"[AWS] Found {len(instances)} EC2 instances", "success")
                return "\n".join(instances) if instances else "No EC2 instances found"
            return "No output"
        except Exception as e:
            return f"AWS EC2 enum failed: {e}"

    def aws_enum_lambda_functions(self, target):
        """Enumerate Lambda functions."""
        self.log(f"[AWS] Enumerating Lambda functions on {target}", "info")
        try:
            output = self.run_command("aws lambda list-functions --output json", timeout=60)
            if output:
                functions = json.loads(output).get("Functions", [])
                result_lines = []
                for f in functions:
                    result_lines.append(
                        f"Function: {f['FunctionName']} | Runtime: {f['Runtime']} "
                        f"| Handler: {f['Handler']} | Role: {f['Role']}"
                    )
                self.log(f"[AWS] Found {len(functions)} Lambda functions", "success")
                return "\n".join(result_lines) if result_lines else "No Lambda functions found"
            return "No output"
        except Exception as e:
            return f"AWS Lambda enum failed: {e}"

    def aws_enum_rds_instances(self, target):
        """Enumerate RDS instances."""
        self.log(f"[AWS] Enumerating RDS instances on {target}", "info")
        try:
            output = self.run_command(
                "aws rds describe-db-instances --output json", timeout=60
            )
            if output:
                instances = json.loads(output).get("DBInstances", [])
                result_lines = []
                for db in instances:
                    result_lines.append(
                        f"DB: {db['DBInstanceIdentifier']} | Engine: {db['Engine']} "
                        f"| Status: {db['DBInstanceStatus']} "
                        f"| Endpoint: {db['Endpoint']['Address']}"
                    )
                self.log(f"[AWS] Found {len(instances)} RDS instances", "success")
                return "\n".join(result_lines) if result_lines else "No RDS instances found"
            return "No output"
        except Exception as e:
            return f"AWS RDS enum failed: {e}"

    def aws_enum_security_groups(self, target):
        """Enumerate security groups with open ports."""
        self.log(f"[AWS] Enumerating security groups on {target}", "info")
        try:
            output = self.run_command(
                "aws ec2 describe-security-groups --output json", timeout=60
            )
            if output:
                groups = json.loads(output).get("SecurityGroups", [])
                result_lines = []
                for sg in groups:
                    open_ports = []
                    for rule in sg.get("IpPermissions", []):
                        from_port = rule.get("FromPort", "N/A")
                        to_port = rule.get("ToPort", "N/A")
                        for cidr in rule.get("IpRanges", []):
                            open_ports.append(f"{from_port}-{to_port} ({cidr['CidrIp']})")
                    result_lines.append(
                        f"SG: {sg['GroupName']} ({sg['GroupId']}) "
                        f"| Open: {', '.join(open_ports[:5]) if open_ports else 'None'}"
                    )
                self.log(f"[AWS] Found {len(groups)} security groups", "success")
                return "\n".join(result_lines) if result_lines else "No security groups found"
            return "No output"
        except Exception as e:
            return f"AWS SG enum failed: {e}"

    def aws_enum_subnets(self, target):
        """Enumerate VPC subnets."""
        self.log(f"[AWS] Enumerating subnets on {target}", "info")
        try:
            output = self.run_command(
                "aws ec2 describe-subnets --output json", timeout=60
            )
            if output:
                subnets = json.loads(output).get("Subnets", [])
                result_lines = []
                for s in subnets:
                    result_lines.append(
                        f"Subnet: {s['SubnetId']} | CIDR: {s['CidrBlock']} "
                        f"| VPC: {s['VpcId']} | AZ: {s['AvailabilityZone']}"
                    )
                self.log(f"[AWS] Found {len(subnets)} subnets", "success")
                return "\n".join(result_lines) if result_lines else "No subnets found"
            return "No output"
        except Exception as e:
            return f"AWS subnet enum failed: {e}"

    def aws_enum_route_tables(self, target):
        """Enumerate route tables."""
        self.log(f"[AWS] Enumerating route tables on {target}", "info")
        try:
            output = self.run_command(
                "aws ec2 describe-route-tables --output json", timeout=60
            )
            if output:
                tables = json.loads(output).get("RouteTables", [])
                result_lines = []
                for rt in tables:
                    routes = [
                        f"{r.get('DestinationCidrBlock', 'N/A')} -> {r.get('GatewayId', r.get('NatGatewayId', 'local'))}"
                        for r in rt.get("Routes", [])
                    ]
                    result_lines.append(
                        f"RT: {rt['RouteTableId']} | VPC: {rt.get('VpcId', 'N/A')} "
                        f"| Routes: {'; '.join(routes[:3])}"
                    )
                self.log(f"[AWS] Found {len(tables)} route tables", "success")
                return "\n".join(result_lines) if result_lines else "No route tables found"
            return "No output"
        except Exception as e:
            return f"AWS route table enum failed: {e}"

    def aws_enum_vpcs(self, target):
        """Enumerate VPCs."""
        self.log(f"[AWS] Enumerating VPCs on {target}", "info")
        try:
            output = self.run_command("aws ec2 describe-vpcs --output json", timeout=60)
            if output:
                vpcs = json.loads(output).get("Vpcs", [])
                result_lines = []
                for v in vpcs:
                    name = next(
                        (t["Value"] for t in v.get("Tags", []) if t["Key"] == "Name"),
                        "N/A",
                    )
                    result_lines.append(
                        f"VPC: {v['VpcId']} | CIDR: {v['CidrBlock']} "
                        f"| Name: {name} | Default: {v.get('IsDefault', False)}"
                    )
                self.log(f"[AWS] Found {len(vpcs)} VPCs", "success")
                return "\n".join(result_lines) if result_lines else "No VPCs found"
            return "No output"
        except Exception as e:
            return f"AWS VPC enum failed: {e}"

    def aws_enum_iam_policies_attached(self, target):
        """Enumerate policies attached to a specific user."""
        self.log(f"[AWS] Enumerating attached policies for {target}", "info")
        try:
            output = self.run_command(
                f"aws iam list-attached-user-policies --user-name {target} --output json",
                timeout=60,
            )
            if output:
                policies = json.loads(output).get("AttachedPolicies", [])
                result_lines = []
                for p in policies:
                    result_lines.append(
                        f"Policy: {p['PolicyName']} | Arn: {p['PolicyArn']}"
                    )
                self.log(f"[AWS] Found {len(policies)} attached policies", "success")
                return "\n".join(result_lines) if result_lines else "No attached policies"
            return "No output"
        except Exception as e:
            return f"AWS policy attach enum failed: {e}"

    def aws_enum_access_keys(self, target):
        """Enumerate access keys for an IAM user."""
        self.log(f"[AWS] Enumerating access keys for user {target}", "info")
        try:
            output = self.run_command(
                f"aws iam list-access-keys --user-name {target} --output json",
                timeout=60,
            )
            if output:
                keys = json.loads(output).get("AccessKeyMetadata", [])
                result_lines = []
                for k in keys:
                    result_lines.append(
                        f"KeyID: {k['AccessKeyId']} | Status: {k['Status']} "
                        f"| Created: {k['CreateDate']}"
                    )
                self.log(f"[AWS] Found {len(keys)} access keys", "success")
                return "\n".join(result_lines) if result_lines else "No access keys found"
            return "No output"
        except Exception as e:
            return f"AWS access key enum failed: {e}"

    def aws_enum_cloudtrail(self, target):
        """Enumerate CloudTrail trails."""
        self.log(f"[AWS] Enumerating CloudTrail trails on {target}", "info")
        try:
            output = self.run_command(
                "aws cloudtrail describe-trails --output json", timeout=60
            )
            if output:
                trails = json.loads(output).get("trailList", [])
                result_lines = []
                for t in trails:
                    result_lines.append(
                        f"Trail: {t['Name']} | S3: {t.get('S3BucketName', 'N/A')} "
                        f"| LogFile: {t.get('LogFileValidationEnabled', 'N/A')}"
                    )
                self.log(f"[AWS] Found {len(trails)} CloudTrail trails", "success")
                return "\n".join(result_lines) if result_lines else "No trails found"
            return "No output"
        except Exception as e:
            return f"AWS CloudTrail enum failed: {e}"

    def aws_enum_route53(self, target):
        """Enumerate Route53 hosted zones."""
        self.log(f"[AWS] Enumerating Route53 zones on {target}", "info")
        try:
            output = self.run_command(
                "aws route53 list-hosted-zones --output json", timeout=60
            )
            if output:
                zones = json.loads(output).get("HostedZones", [])
                result_lines = []
                for z in zones:
                    result_lines.append(
                        f"Zone: {z['Name']} | ID: {z['Id']} "
                        f"| Records: {z.get('ResourceRecordSetCount', 'N/A')}"
                    )
                self.log(f"[AWS] Found {len(zones)} hosted zones", "success")
                return "\n".join(result_lines) if result_lines else "No hosted zones found"
            return "No output"
        except Exception as e:
            return f"AWS Route53 enum failed: {e}"

    def aws_enum_sqs_queues(self, target):
        """Enumerate SQS queues."""
        self.log(f"[AWS] Enumerating SQS queues on {target}", "info")
        try:
            output = self.run_command(
                "aws sqs list-queues --output json", timeout=60
            )
            if output:
                queues = json.loads(output).get("QueueUrls", [])
                result_lines = []
                for q in queues:
                    result_lines.append(f"Queue: {q}")
                self.log(f"[AWS] Found {len(queues)} SQS queues", "success")
                return "\n".join(result_lines) if result_lines else "No SQS queues found"
            return "No output"
        except Exception as e:
            return f"AWS SQS enum failed: {e}"

    def aws_enum_sns_topics(self, target):
        """Enumerate SNS topics."""
        self.log(f"[AWS] Enumerating SNS topics on {target}", "info")
        try:
            output = self.run_command(
                "aws sns list-topics --output json", timeout=60
            )
            if output:
                topics = json.loads(output).get("Topics", [])
                result_lines = []
                for t in topics:
                    result_lines.append(f"Topic: {t['TopicArn']}")
                self.log(f"[AWS] Found {len(topics)} SNS topics", "success")
                return "\n".join(result_lines) if result_lines else "No SNS topics found"
            return "No output"
        except Exception as e:
            return f"AWS SNS enum failed: {e}"

    def aws_pacu_enum(self, target):
        """Run Pacu for comprehensive AWS enumeration."""
        self.log(f"[AWS] Running Pacu enumeration module on {target}", "info")
        try:
            output = self.run_command(
                "pacu --module-name iam__enum_users --session-name blacksentinel "
                "--exec-id default --module-args {}",
                timeout=120,
            )
            if output:
                self.log("[AWS] Pacu enumeration complete", "success")
                return output
            return "Pacu not installed or no output"
        except Exception as e:
            return f"Pacu enum failed: {e}"

    def aws_pacu_privesc(self, target):
        """Run Pacu for privilege escalation paths."""
        self.log(f"[AWS] Running Pacu privesc module on {target}", "info")
        try:
            output = self.run_command(
                "pacu --module-name iam__privesc_scan --session-name blacksentinel "
                "--exec-id default --module-args {}",
                timeout=120,
            )
            if output:
                self.log("[AWS] Pacu privesc scan complete", "success")
                return output
            return "Pacu not installed or no output"
        except Exception as e:
            return f"Pacu privesc failed: {e}"

    def aws_pacu_lateral_movement(self, target):
        """Run Pacu for lateral movement discovery."""
        self.log(f"[AWS] Running Pacu lateral movement module on {target}", "info")
        try:
            output = self.run_command(
                "pacu --module-name iam__enum_roles_policies --session-name blacksentinel "
                "--exec-id default --module-args {}",
                timeout=120,
            )
            if output:
                self.log("[AWS] Pacu lateral movement scan complete", "success")
                return output
            return "Pacu not installed or no output"
        except Exception as e:
            return f"Pacu lateral movement failed: {e}"

    def aws_check_public_access(self, target):
        """Check for publicly accessible resources."""
        self.log(f"[AWS] Checking public access on {target}", "info")
        try:
            lines = []
            s3_output = self.run_command("aws s3api list-buckets --query 'Buckets[].Name' --output text", timeout=30)
            if s3_output:
                for bucket in s3_output.strip().split():
                    acl = self.run_command(
                        f"aws s3api get-bucket-acl --bucket {bucket} --output json",
                        timeout=30,
                    )
                    if acl and "AllUsers" in acl:
                        lines.append(f"[PUBLIC S3] {bucket} - ACL contains AllUsers")
            sg_output = self.run_command(
                "aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].{GroupId:GroupId,GroupName:GroupName}' --output json",
                timeout=30,
            )
            if sg_output:
                groups = json.loads(sg_output)
                for g in groups:
                    lines.append(
                        f"[PUBLIC SG] {g['GroupName']} ({g['GroupId']}) - open to 0.0.0.0/0"
                    )
            self.log(f"[AWS] Public access check complete: {len(lines)} findings", "success")
            return "\n".join(lines) if lines else "No public resources found"
        except Exception as e:
            return f"AWS public access check failed: {e}"

    # ══════════════════════════════════════════════════════════
    #  AZURE ATTACKS (20 methods)
    # ══════════════════════════════════════════════════════════

    def azure_enum_users(self, target):
        """Enumerate Azure AD users."""
        self.log(f"[Azure] Enumerating users on {target}", "info")
        try:
            output = self.run_command(
                "az ad user list --output json", timeout=60
            )
            if output:
                users = json.loads(output)
                result_lines = []
                for u in users:
                    result_lines.append(
                        f"User: {u.get('userPrincipalName', 'N/A')} "
                        f"| DisplayName: {u.get('displayName', 'N/A')} "
                        f"| Enabled: {u.get('accountEnabled', 'N/A')}"
                    )
                self.log(f"[Azure] Found {len(users)} users", "success")
                return "\n".join(result_lines) if result_lines else "No users found"
            return "No output from az CLI"
        except Exception as e:
            return f"Azure user enum failed: {e}"

    def azure_enum_groups(self, target):
        """Enumerate Azure AD groups."""
        self.log(f"[Azure] Enumerating groups on {target}", "info")
        try:
            output = self.run_command("az ad group list --output json", timeout=60)
            if output:
                groups = json.loads(output)
                result_lines = []
                for g in groups:
                    result_lines.append(
                        f"Group: {g.get('displayName', 'N/A')} "
                        f"| Mail: {g.get('mail', 'N/A')} "
                        f"| Created: {g.get('createdDateTime', 'N/A')}"
                    )
                self.log(f"[Azure] Found {len(groups)} groups", "success")
                return "\n".join(result_lines) if result_lines else "No groups found"
            return "No output"
        except Exception as e:
            return f"Azure group enum failed: {e}"

    def azure_enum_subscriptions(self, target):
        """Enumerate Azure subscriptions."""
        self.log(f"[Azure] Enumerating subscriptions on {target}", "info")
        try:
            output = self.run_command("az account list --output json", timeout=60)
            if output:
                subs = json.loads(output)
                result_lines = []
                for s in subs:
                    result_lines.append(
                        f"Sub: {s.get('name', 'N/A')} "
                        f"| ID: {s.get('id', 'N/A')} "
                        f"| State: {s.get('state', 'N/A')}"
                    )
                self.log(f"[Azure] Found {len(subs)} subscriptions", "success")
                return "\n".join(result_lines) if result_lines else "No subscriptions found"
            return "No output"
        except Exception as e:
            return f"Azure subscription enum failed: {e}"

    def azure_enum_vms(self, target):
        """Enumerate Azure VMs across subscriptions."""
        self.log(f"[Azure] Enumerating VMs on {target}", "info")
        try:
            output = self.run_command(
                "az vm list --show-details --output json", timeout=60
            )
            if output:
                vms = json.loads(output)
                result_lines = []
                for v in vms:
                    result_lines.append(
                        f"VM: {v.get('name', 'N/A')} "
                        f"| Status: {v.get('powerState', 'N/A')} "
                        f"| OS: {v.get('osType', 'N/A')} "
                        f"| PrivateIP: {v.get('privateIps', 'N/A')}"
                    )
                self.log(f"[Azure] Found {len(vms)} VMs", "success")
                return "\n".join(result_lines) if result_lines else "No VMs found"
            return "No output"
        except Exception as e:
            return f"Azure VM enum failed: {e}"

    def azure_enum_storage_accounts(self, target):
        """Enumerate storage accounts."""
        self.log(f"[Azure] Enumerating storage accounts on {target}", "info")
        try:
            output = self.run_command(
                "az storage account list --output json", timeout=60
            )
            if output:
                accounts = json.loads(output)
                result_lines = []
                for a in accounts:
                    result_lines.append(
                        f"Account: {a.get('name', 'N/A')} "
                        f"| Kind: {a.get('kind', 'N/A')} "
                        f"| Location: {a.get('location', 'N/A')} "
                        f"| PublicAccess: {a.get('allowBlobPublicAccess', 'N/A')}"
                    )
                self.log(f"[Azure] Found {len(accounts)} storage accounts", "success")
                return "\n".join(result_lines) if result_lines else "No storage accounts found"
            return "No output"
        except Exception as e:
            return f"Azure storage enum failed: {e}"

    def azure_enum_nsgs(self, target):
        """Enumerate Network Security Groups."""
        self.log(f"[Azure] Enumerating NSGs on {target}", "info")
        try:
            output = self.run_command(
                "az network nsg list --output json", timeout=60
            )
            if output:
                nsgs = json.loads(output)
                result_lines = []
                for nsg in nsgs:
                    rules = nsg.get("securityRules", [])
                    open_rules = [
                        r["name"] for r in rules
                        if r.get("access") == "Allow"
                        and r.get("direction") == "Inbound"
                        and r.get("sourceAddressPrefix") in ("*", "0.0.0.0/0", "Internet")
                    ]
                    result_lines.append(
                        f"NSG: {nsg.get('name', 'N/A')} "
                        f"| OpenRules: {', '.join(open_rules[:5]) if open_rules else 'None'}"
                    )
                self.log(f"[Azure] Found {len(nsgs)} NSGs", "success")
                return "\n".join(result_lines) if result_lines else "No NSGs found"
            return "No output"
        except Exception as e:
            return f"Azure NSG enum failed: {e}"

    def azure_enum_key_vaults(self, target):
        """Enumerate Key Vaults."""
        self.log(f"[Azure] Enumerating Key Vaults on {target}", "info")
        try:
            output = self.run_command(
                "az keyvault list --output json", timeout=60
            )
            if output:
                vaults = json.loads(output)
                result_lines = []
                for v in vaults:
                    result_lines.append(
                        f"Vault: {v.get('name', 'N/A')} "
                        f"| Location: {v.get('location', 'N/A')} "
                        f"| VaultURI: {v.get('vaultUri', 'N/A')}"
                    )
                self.log(f"[Azure] Found {len(vaults)} Key Vaults", "success")
                return "\n".join(result_lines) if result_lines else "No Key Vaults found"
            return "No output"
        except Exception as e:
            return f"Azure Key Vault enum failed: {e}"

    def azure_enum_app_registrations(self, target):
        """Enumerate App Registrations."""
        self.log(f"[Azure] Enumerating App Registrations on {target}", "info")
        try:
            output = self.run_command(
                "az ad app list --output json", timeout=60
            )
            if output:
                apps = json.loads(output)
                result_lines = []
                for a in apps:
                    result_lines.append(
                        f"App: {a.get('displayName', 'N/A')} "
                        f"| AppID: {a.get('appId', 'N/A')} "
                        f"| Owners: {len(a.get('owners', []))}"
                    )
                self.log(f"[Azure] Found {len(apps)} App Registrations", "success")
                return "\n".join(result_lines) if result_lines else "No App Registrations found"
            return "No output"
        except Exception as e:
            return f"Azure App Reg enum failed: {e}"

    def azure_enum_service_principals(self, target):
        """Enumerate service principals."""
        self.log(f"[Azure] Enumerating service principals on {target}", "info")
        try:
            output = self.run_command(
                "az ad sp list --all --output json", timeout=120
            )
            if output:
                sps = json.loads(output)
                result_lines = []
                for sp in sps:
                    result_lines.append(
                        f"SP: {sp.get('displayName', 'N/A')} "
                        f"| AppID: {sp.get('appId', 'N/A')} "
                        f"| Type: {sp.get('servicePrincipalType', 'N/A')}"
                    )
                self.log(f"[Azure] Found {len(sps)} service principals", "success")
                return "\n".join(result_lines[:50]) if result_lines else "No service principals found"
            return "No output"
        except Exception as e:
            return f"Azure SP enum failed: {e}"

    def azure_enum_resource_groups(self, target):
        """Enumerate resource groups."""
        self.log(f"[Azure] Enumerating resource groups on {target}", "info")
        try:
            output = self.run_command(
                "az group list --output json", timeout=60
            )
            if output:
                groups = json.loads(output)
                result_lines = []
                for g in groups:
                    result_lines.append(
                        f"RG: {g.get('name', 'N/A')} "
                        f"| Location: {g.get('location', 'N/A')} "
                        f"| ProvisioningState: {g.get('provisioningState', 'N/A')}"
                    )
                self.log(f"[Azure] Found {len(groups)} resource groups", "success")
                return "\n".join(result_lines) if result_lines else "No resource groups found"
            return "No output"
        except Exception as e:
            return f"Azure RG enum failed: {e}"

    def azure_enum_aks_clusters(self, target):
        """Enumerate AKS clusters."""
        self.log(f"[Azure] Enumerating AKS clusters on {target}", "info")
        try:
            output = self.run_command(
                "az aks list --output json", timeout=60
            )
            if output:
                clusters = json.loads(output)
                result_lines = []
                for c in clusters:
                    result_lines.append(
                        f"Cluster: {c.get('name', 'N/A')} "
                        f"| Status: {c.get('powerState', {}).get('code', 'N/A')} "
                        f"| K8sVersion: {c.get('kubernetesVersion', 'N/A')} "
                        f"| DNS: {c.get('fqdn', 'N/A')}"
                    )
                self.log(f"[Azure] Found {len(clusters)} AKS clusters", "success")
                return "\n".join(result_lines) if result_lines else "No AKS clusters found"
            return "No output"
        except Exception as e:
            return f"Azure AKS enum failed: {e}"

    def azure_enum_functions(self, target):
        """Enumerate Azure Functions."""
        self.log(f"[Azure] Enumerating Functions on {target}", "info")
        try:
            output = self.run_command(
                "az functionapp list --output json", timeout=60
            )
            if output:
                apps = json.loads(output)
                result_lines = []
                for a in apps:
                    result_lines.append(
                        f"Function: {a.get('name', 'N/A')} "
                        f"| State: {a.get('state', 'N/A')} "
                        f"| Runtime: {a.get('siteConfig', {}).get('linuxFxVersion', 'N/A')}"
                    )
                self.log(f"[Azure] Found {len(apps)} Function Apps", "success")
                return "\n".join(result_lines) if result_lines else "No Functions found"
            return "No output"
        except Exception as e:
            return f"Azure Functions enum failed: {e}"

    def azure_enum_cosmosdb(self, target):
        """Enumerate Cosmos DB accounts."""
        self.log(f"[Azure] Enumerating Cosmos DB on {target}", "info")
        try:
            output = self.run_command(
                "az cosmosdb list --output json", timeout=60
            )
            if output:
                accounts = json.loads(output)
                result_lines = []
                for a in accounts:
                    result_lines.append(
                        f"CosmosDB: {a.get('name', 'N/A')} "
                        f"| Location: {a.get('location', 'N/A')} "
                        f"| ProvisioningState: {a.get('provisioningState', 'N/A')}"
                    )
                self.log(f"[Azure] Found {len(accounts)} Cosmos DB accounts", "success")
                return "\n".join(result_lines) if result_lines else "No Cosmos DB accounts found"
            return "No output"
        except Exception as e:
            return f"Azure Cosmos DB enum failed: {e}"

    def azure_enum_managed_disks(self, target):
        """Enumerate managed disks."""
        self.log(f"[Azure] Enumerating managed disks on {target}", "info")
        try:
            output = self.run_command(
                "az disk list --output json", timeout=60
            )
            if output:
                disks = json.loads(output)
                result_lines = []
                for d in disks:
                    result_lines.append(
                        f"Disk: {d.get('name', 'N/A')} "
                        f"| SizeGB: {d.get('diskSizeGB', 'N/A')} "
                        f"| OS: {d.get('osType', 'N/A')} "
                        f"| State: {d.get('diskState', 'N/A')}"
                    )
                self.log(f"[Azure] Found {len(disks)} managed disks", "success")
                return "\n".join(result_lines) if result_lines else "No disks found"
            return "No output"
        except Exception as e:
            return f"Azure disk enum failed: {e}"

    def azure_enum_virtual_networks(self, target):
        """Enumerate virtual networks."""
        self.log(f"[Azure] Enumerating VNets on {target}", "info")
        try:
            output = self.run_command(
                "az network vnet list --output json", timeout=60
            )
            if output:
                vnets = json.loads(output)
                result_lines = []
                for v in vnets:
                    subnets = [s.get("name", "N/A") for s in v.get("subnets", [])]
                    result_lines.append(
                        f"VNet: {v.get('name', 'N/A')} "
                        f"| CIDR: {v.get('addressSpace', {}).get('addressPrefixes', ['N/A'])[0]} "
                        f"| Subnets: {', '.join(subnets[:5])}"
                    )
                self.log(f"[Azure] Found {len(vnets)} VNets", "success")
                return "\n".join(result_lines) if result_lines else "No VNets found"
            return "No output"
        except Exception as e:
            return f"Azure VNet enum failed: {e}"

    def azure_enum_public_ips(self, target):
        """Enumerate public IP addresses."""
        self.log(f"[Azure] Enumerating public IPs on {target}", "info")
        try:
            output = self.run_command(
                "az network public-ip list --output json", timeout=60
            )
            if output:
                ips = json.loads(output)
                result_lines = []
                for ip in ips:
                    result_lines.append(
                        f"IP: {ip.get('name', 'N/A')} "
                        f"| Address: {ip.get('ipAddress', 'N/A')} "
                        f"| Allocation: {ip.get('publicIpAllocationMethod', 'N/A')}"
                    )
                self.log(f"[Azure] Found {len(ips)} public IPs", "success")
                return "\n".join(result_lines) if result_lines else "No public IPs found"
            return "No output"
        except Exception as e:
            return f"Azure public IP enum failed: {e}"

    def azure_enum_role_assignments(self, target):
        """Enumerate role assignments."""
        self.log(f"[Azure] Enumerating role assignments on {target}", "info")
        try:
            output = self.run_command(
                "az role assignment list --all --output json", timeout=60
            )
            if output:
                assignments = json.loads(output)
                result_lines = []
                for a in assignments:
                    result_lines.append(
                        f"Principal: {a.get('principalName', 'N/A')} "
                        f"| Role: {a.get('roleDefinitionName', 'N/A')} "
                        f"| Scope: {a.get('scope', 'N/A')}"
                    )
                self.log(f"[Azure] Found {len(assignments)} role assignments", "success")
                return "\n".join(result_lines[:30]) if result_lines else "No role assignments found"
            return "No output"
        except Exception as e:
            return f"Azure role assignment enum failed: {e}"

    def azure_enum_databases(self, target):
        """Enumerate SQL databases."""
        self.log(f"[Azure] Enumerating SQL databases on {target}", "info")
        try:
            output = self.run_command(
                "az sql db list --output json", timeout=60
            )
            if output:
                dbs = json.loads(output)
                result_lines = []
                for d in dbs:
                    result_lines.append(
                        f"DB: {d.get('name', 'N/A')} "
                        f"| Server: {d.get('serverName', 'N/A')} "
                        f"| Status: {d.get('status', 'N/A')} "
                        f"| Edition: {d.get('edition', 'N/A')}"
                    )
                self.log(f"[Azure] Found {len(dbs)} SQL databases", "success")
                return "\n".join(result_lines) if result_lines else "No SQL databases found"
            return "No output"
        except Exception as e:
            return f"Azure SQL enum failed: {e}"

    def azure_enum_container_registries(self, target):
        """Enumerate container registries."""
        self.log(f"[Azure] Enumerating container registries on {target}", "info")
        try:
            output = self.run_command(
                "az acr list --output json", timeout=60
            )
            if output:
                registries = json.loads(output)
                result_lines = []
                for r in registries:
                    result_lines.append(
                        f"Registry: {r.get('name', 'N/A')} "
                        f"| LoginServer: {r.get('loginServer', 'N/A')} "
                        f"| Sku: {r.get('sku', {}).get('name', 'N/A')}"
                    )
                self.log(f"[Azure] Found {len(registries)} container registries", "success")
                return "\n".join(result_lines) if result_lines else "No registries found"
            return "No output"
        except Exception as e:
            return f"Azure ACR enum failed: {e}"

    # ══════════════════════════════════════════════════════════
    #  GCP ATTACKS (20 methods)
    # ══════════════════════════════════════════════════════════

    def gcp_enum_projects(self, target):
        """Enumerate GCP projects."""
        self.log(f"[GCP] Enumerating projects on {target}", "info")
        try:
            output = self.run_command(
                "gcloud projects list --format=json", timeout=60
            )
            if output:
                projects = json.loads(output)
                result_lines = []
                for p in projects:
                    result_lines.append(
                        f"Project: {p.get('projectId', 'N/A')} "
                        f"| Name: {p.get('name', 'N/A')} "
                        f"| Number: {p.get('projectNumber', 'N/A')} "
                        f"| Lifecycle: {p.get('lifecycleState', 'N/A')}"
                    )
                self.log(f"[GCP] Found {len(projects)} projects", "success")
                return "\n".join(result_lines) if result_lines else "No projects found"
            return "No output from gcloud"
        except Exception as e:
            return f"GCP project enum failed: {e}"

    def gcp_enum_instances(self, target):
        """Enumerate GCE instances across zones."""
        self.log(f"[GCP] Enumerating GCE instances on {target}", "info")
        try:
            output = self.run_command(
                "gcloud compute instances list --format=json", timeout=60
            )
            if output:
                instances = json.loads(output)
                result_lines = []
                for inst in instances:
                    result_lines.append(
                        f"Instance: {inst.get('name', 'N/A')} "
                        f"| Zone: {inst.get('zone', 'N/A')} "
                        f"| Status: {inst.get('status', 'N/A')} "
                        f"| IP: {inst.get('networkInterfaces', [{}])[0].get('networkIP', 'N/A')}"
                    )
                self.log(f"[GCP] Found {len(instances)} GCE instances", "success")
                return "\n".join(result_lines) if result_lines else "No GCE instances found"
            return "No output"
        except Exception as e:
            return f"GCP instance enum failed: {e}"

    def gcp_enum_buckets(self, target):
        """Enumerate GCS buckets."""
        self.log(f"[GCP] Enumerating GCS buckets on {target}", "info")
        try:
            output = self.run_command("gsutil ls -p {} -L".format(target), timeout=60)
            if output:
                lines = output.strip().split("\n")
                buckets = [l for l in lines if l.startswith("gs://")]
                result_lines = []
                for b in buckets:
                    result_lines.append(f"Bucket: {b}")
                self.log(f"[GCP] Found {len(buckets)} buckets", "success")
                return "\n".join(result_lines) if result_lines else "No buckets found"
            return "No output"
        except Exception as e:
            return f"GCP bucket enum failed: {e}"

    def gcp_enum_iam_bindings(self, target):
        """Enumerate IAM bindings for a project."""
        self.log(f"[GCP] Enumerating IAM bindings on {target}", "info")
        try:
            output = self.run_command(
                f"gcloud projects get-iam-policy {target} --format=json", timeout=60
            )
            if output:
                policy = json.loads(output)
                bindings = policy.get("bindings", [])
                result_lines = []
                for b in bindings:
                    members = ", ".join(b.get("members", [])[:5])
                    result_lines.append(
                        f"Role: {b.get('role', 'N/A')} | Members: {members}"
                    )
                self.log(f"[GCP] Found {len(bindings)} IAM bindings", "success")
                return "\n".join(result_lines) if result_lines else "No IAM bindings found"
            return "No output"
        except Exception as e:
            return f"GCP IAM enum failed: {e}"

    def gcp_enum_service_accounts(self, target):
        """Enumerate service accounts."""
        self.log(f"[GCP] Enumerating service accounts on {target}", "info")
        try:
            output = self.run_command(
                f"gcloud iam service-accounts list --project={target} --format=json",
                timeout=60,
            )
            if output:
                accounts = json.loads(output)
                result_lines = []
                for a in accounts:
                    result_lines.append(
                        f"SA: {a.get('email', 'N/A')} "
                        f"| Name: {a.get('displayName', 'N/A')} "
                        f"| Disabled: {a.get('disabled', 'N/A')}"
                    )
                self.log(f"[GCP] Found {len(accounts)} service accounts", "success")
                return "\n".join(result_lines) if result_lines else "No service accounts found"
            return "No output"
        except Exception as e:
            return f"GCP SA enum failed: {e}"

    def gcp_enum_firewall_rules(self, target):
        """Enumerate firewall rules."""
        self.log(f"[GCP] Enumerating firewall rules on {target}", "info")
        try:
            output = self.run_command(
                "gcloud compute firewall-rules list --format=json", timeout=60
            )
            if output:
                rules = json.loads(output)
                result_lines = []
                for r in rules:
                    allowed = []
                    for a in r.get("allowed", []):
                        proto = a.get("IPProtocol", "N/A")
                        ports = a.get("ports", ["all"])
                        allowed.append(f"{proto}:{','.join(ports)}")
                    result_lines.append(
                        f"Rule: {r.get('name', 'N/A')} "
                        f"| Direction: {r.get('direction', 'N/A')} "
                        f"| Allowed: {'; '.join(allowed[:3])} "
                        f"| Source: {r.get('sourceRanges', ['N/A'])[0] if r.get('sourceRanges') else 'N/A'}"
                    )
                self.log(f"[GCP] Found {len(rules)} firewall rules", "success")
                return "\n".join(result_lines) if result_lines else "No firewall rules found"
            return "No output"
        except Exception as e:
            return f"GCP firewall enum failed: {e}"

    def gcp_enum_networks(self, target):
        """Enumerate VPC networks."""
        self.log(f"[GCP] Enumerating VPC networks on {target}", "info")
        try:
            output = self.run_command(
                "gcloud compute networks list --format=json", timeout=60
            )
            if output:
                networks = json.loads(output)
                result_lines = []
                for n in networks:
                    result_lines.append(
                        f"Network: {n.get('name', 'N/A')} "
                        f"| Mode: {n.get('autoCreateSubnetworks', 'N/A')} "
                        f"| Routing: {n.get('routingConfig', {}).get('routingMode', 'N/A')}"
                    )
                self.log(f"[GCP] Found {len(networks)} networks", "success")
                return "\n".join(result_lines) if result_lines else "No networks found"
            return "No output"
        except Exception as e:
            return f"GCP network enum failed: {e}"

    def gcp_enum_subnets(self, target):
        """Enumerate subnets."""
        self.log(f"[GCP] Enumerating subnets on {target}", "info")
        try:
            output = self.run_command(
                "gcloud compute networks subnets list --format=json", timeout=60
            )
            if output:
                subnets = json.loads(output)
                result_lines = []
                for s in subnets:
                    result_lines.append(
                        f"Subnet: {s.get('name', 'N/A')} "
                        f"| CIDR: {s.get('ipCidrRange', 'N/A')} "
                        f"| Region: {s.get('region', 'N/A')} "
                        f"| Network: {s.get('network', 'N/A')}"
                    )
                self.log(f"[GCP] Found {len(subnets)} subnets", "success")
                return "\n".join(result_lines) if result_lines else "No subnets found"
            return "No output"
        except Exception as e:
            return f"GCP subnet enum failed: {e}"

    def gcp_enum_cloud_sql(self, target):
        """Enumerate Cloud SQL instances."""
        self.log(f"[GCP] Enumerating Cloud SQL on {target}", "info")
        try:
            output = self.run_command(
                f"gcloud sql instances list --format=json", timeout=60
            )
            if output:
                instances = json.loads(output)
                result_lines = []
                for inst in instances:
                    result_lines.append(
                        f"Instance: {inst.get('name', 'N/A')} "
                        f"| DB: {inst.get('databaseVersion', 'N/A')} "
                        f"| Tier: {inst.get('settings', {}).get('tier', 'N/A')} "
                        f"| IP: {inst.get('ipAddresses', [{}])[0].get('ipAddress', 'N/A')}"
                    )
                self.log(f"[GCP] Found {len(instances)} Cloud SQL instances", "success")
                return "\n".join(result_lines) if result_lines else "No Cloud SQL found"
            return "No output"
        except Exception as e:
            return f"GCP Cloud SQL enum failed: {e}"

    def gcp_enum_gke_clusters(self, target):
        """Enumerate GKE clusters."""
        self.log(f"[GCP] Enumerating GKE clusters on {target}", "info")
        try:
            output = self.run_command(
                f"gcloud container clusters list --format=json", timeout=60
            )
            if output:
                clusters = json.loads(output)
                result_lines = []
                for c in clusters:
                    result_lines.append(
                        f"Cluster: {c.get('name', 'N/A')} "
                        f"| Status: {c.get('status', 'N/A')} "
                        f"| Version: {c.get('currentMasterVersion', 'N/A')} "
                        f"| Location: {c.get('location', 'N/A')}"
                    )
                self.log(f"[GCP] Found {len(clusters)} GKE clusters", "success")
                return "\n".join(result_lines) if result_lines else "No GKE clusters found"
            return "No output"
        except Exception as e:
            return f"GCP GKE enum failed: {e}"

    def gcp_enum_cloud_functions(self, target):
        """Enumerate Cloud Functions."""
        self.log(f"[GCP] Enumerating Cloud Functions on {target}", "info")
        try:
            output = self.run_command(
                "gcloud functions list --format=json", timeout=60
            )
            if output:
                functions = json.loads(output)
                result_lines = []
                for f in functions:
                    result_lines.append(
                        f"Function: {f.get('name', 'N/A')} "
                        f"| Status: {f.get('status', 'N/A')} "
                        f"| Runtime: {f.get('runtime', 'N/A')} "
                        f"| Trigger: {f.get('trigger', {}).get('eventType', 'N/A')}"
                    )
                self.log(f"[GCP] Found {len(functions)} Cloud Functions", "success")
                return "\n".join(result_lines) if result_lines else "No Cloud Functions found"
            return "No output"
        except Exception as e:
            return f"GCP Cloud Functions enum failed: {e}"

    def gcp_enum_pubsub(self, target):
        """Enumerate Pub/Sub topics."""
        self.log(f"[GCP] Enumerating Pub/Sub topics on {target}", "info")
        try:
            output = self.run_command(
                "gcloud pubsub topics list --format=json", timeout=60
            )
            if output:
                topics = json.loads(output)
                result_lines = []
                for t in topics:
                    result_lines.append(f"Topic: {t.get('name', 'N/A')}")
                self.log(f"[GCP] Found {len(topics)} Pub/Sub topics", "success")
                return "\n".join(result_lines) if result_lines else "No Pub/Sub topics found"
            return "No output"
        except Exception as e:
            return f"GCP Pub/Sub enum failed: {e}"

    def gcp_enum_cloud_run(self, target):
        """Enumerate Cloud Run services."""
        self.log(f"[GCP] Enumerating Cloud Run on {target}", "info")
        try:
            output = self.run_command(
                "gcloud run services list --format=json --platform=managed", timeout=60
            )
            if output:
                services = json.loads(output)
                result_lines = []
                for s in services:
                    result_lines.append(
                        f"Service: {s.get('metadata', {}).get('name', 'N/A')} "
                        f"| URL: {s.get('status', {}).get('url', 'N/A')} "
                        f"| Region: {s.get('metadata', {}).get('labels', {}).get('cloud.googleapis.com/location', 'N/A')}"
                    )
                self.log(f"[GCP] Found {len(services)} Cloud Run services", "success")
                return "\n".join(result_lines) if result_lines else "No Cloud Run services found"
            return "No output"
        except Exception as e:
            return f"GCP Cloud Run enum failed: {e}"

    def gcp_enum_cloud_build(self, target):
        """Enumerate Cloud Build triggers."""
        self.log(f"[GCP] Enumerating Cloud Build on {target}", "info")
        try:
            output = self.run_command(
                "gcloud builds triggers list --format=json", timeout=60
            )
            if output:
                triggers = json.loads(output)
                result_lines = []
                for t in triggers:
                    result_lines.append(
                        f"Trigger: {t.get('name', 'N/A')} "
                        f"| Repo: {t.get('github', {}).get('owner', 'N/A')}/{t.get('github', {}).get('name', 'N/A')} "
                        f"| Branch: {t.get('triggerTemplate', {}).get('branchName', 'N/A')}"
                    )
                self.log(f"[GCP] Found {len(triggers)} Cloud Build triggers", "success")
                return "\n".join(result_lines) if result_lines else "No Cloud Build triggers found"
            return "No output"
        except Exception as e:
            return f"GCP Cloud Build enum failed: {e}"

    def gcp_enum_bigquery(self, target):
        """Enumerate BigQuery datasets."""
        self.log(f"[GCP] Enumerating BigQuery datasets on {target}", "info")
        try:
            output = self.run_command(
                f"bq ls --format=json {target}:", timeout=60
            )
            if output:
                datasets = json.loads(output)
                result_lines = []
                for d in datasets:
                    result_lines.append(
                        f"Dataset: {d.get('datasetReference', {}).get('datasetId', 'N/A')} "
                        f"| FriendlyName: {d.get('friendlyName', 'N/A')} "
                        f"| CreationTime: {d.get('creationTime', 'N/A')}"
                    )
                self.log(f"[GCP] Found {len(datasets)} BigQuery datasets", "success")
                return "\n".join(result_lines) if result_lines else "No BigQuery datasets found"
            return "No output"
        except Exception as e:
            return f"GCP BigQuery enum failed: {e}"

    def gcp_enum_cloud_storage_iam(self, target):
        """Check IAM policies on GCS buckets."""
        self.log(f"[GCP] Checking GCS bucket IAM on {target}", "info")
        try:
            output = self.run_command("gsutil ls -p {} -b".format(target), timeout=30)
            if not output:
                return "No buckets found"
            buckets = [l.strip().rstrip("/") for l in output.strip().split("\n") if l.startswith("gs://")]
            result_lines = []
            for bucket in buckets:
                iam = self.run_command(
                    f"gsutil iam get {bucket}", timeout=30
                )
                if iam:
                    result_lines.append(f"Bucket: {bucket}")
                    result_lines.append(iam[:500])
            self.log(f"[GCP] Checked {len(buckets)} buckets for IAM", "success")
            return "\n".join(result_lines) if result_lines else "No IAM data found"
        except Exception as e:
            return f"GCP GCS IAM check failed: {e}"

    def gcp_enum_cloud_endpoints(self, target):
        """Enumerate Cloud Endpoints services."""
        self.log(f"[GCP] Enumerating Cloud Endpoints on {target}", "info")
        try:
            output = self.run_command(
                f"gcloud endpoints services list --format=json --project={target}",
                timeout=60,
            )
            if output:
                services = json.loads(output)
                result_lines = []
                for s in services:
                    result_lines.append(
                        f"Service: {s.get('serviceName', 'N/A')} "
                        f"| Config: {s.get('config', 'N/A')} "
                        f"| State: {s.get('state', 'N/A')}"
                    )
                self.log(f"[GCP] Found {len(services)} Endpoints services", "success")
                return "\n".join(result_lines) if result_lines else "No Endpoints services found"
            return "No output"
        except Exception as e:
            return f"GCP Endpoints enum failed: {e}"

    def gcp_enum_compute_addresses(self, target):
        """Enumerate static IP addresses."""
        self.log(f"[GCP] Enumerating static IPs on {target}", "info")
        try:
            output = self.run_command(
                "gcloud compute addresses list --format=json", timeout=60
            )
            if output:
                addresses = json.loads(output)
                result_lines = []
                for a in addresses:
                    result_lines.append(
                        f"Address: {a.get('name', 'N/A')} "
                        f"| IP: {a.get('address', 'N/A')} "
                        f"| Status: {a.get('status', 'N/A')} "
                        f"| Region: {a.get('region', 'N/A')}"
                    )
                self.log(f"[GCP] Found {len(addresses)} static IPs", "success")
                return "\n".join(result_lines) if result_lines else "No static IPs found"
            return "No output"
        except Exception as e:
            return f"GCP static IP enum failed: {e}"

    def gcp_enum_logging_sinks(self, target):
        """Enumerate logging sinks."""
        self.log(f"[GCP] Enumerating logging sinks on {target}", "info")
        try:
            output = self.run_command(
                f"gcloud logging sinks list --format=json --project={target}",
                timeout=60,
            )
            if output:
                sinks = json.loads(output)
                result_lines = []
                for s in sinks:
                    result_lines.append(
                        f"Sink: {s.get('name', 'N/A')} "
                        f"| Destination: {s.get('destination', 'N/A')} "
                        f"| Filter: {s.get('filter', 'N/A')[:80]}"
                    )
                self.log(f"[GCP] Found {len(sinks)} logging sinks", "success")
                return "\n".join(result_lines) if result_lines else "No logging sinks found"
            return "No output"
        except Exception as e:
            return f"GCP logging sink enum failed: {e}"

    def gcp_enum_secret_manager(self, target):
        """Enumerate Secret Manager secrets."""
        self.log(f"[GCP] Enumerating secrets on {target}", "info")
        try:
            output = self.run_command(
                "gcloud secrets list --format=json", timeout=60
            )
            if output:
                secrets = json.loads(output)
                result_lines = []
                for s in secrets:
                    result_lines.append(
                        f"Secret: {s.get('name', 'N/A')} "
                        f"| Created: {s.get('createTime', 'N/A')} "
                        f"| Labels: {s.get('labels', {})}"
                    )
                self.log(f"[GCP] Found {len(secrets)} secrets", "success")
                return "\n".join(result_lines) if result_lines else "No secrets found"
            return "No output"
        except Exception as e:
            return f"GCP Secret Manager enum failed: {e}"

    def gcp_enum_artifact_registry(self, target):
        """Enumerate Artifact Registry repositories."""
        self.log(f"[GCP] Enumerating Artifact Registry on {target}", "info")
        try:
            output = self.run_command(
                f"gcloud artifacts repositories list --format=json --project={target}",
                timeout=60,
            )
            if output:
                repos = json.loads(output)
                result_lines = []
                for r in repos:
                    result_lines.append(
                        f"Repo: {r.get('name', 'N/A')} "
                        f"| Format: {r.get('format', 'N/A')} "
                        f"| Mode: {r.get('mode', 'N/A')} "
                        f"| Location: {r.get('location', 'N/A')}"
                    )
                self.log(f"[GCP] Found {len(repos)} Artifact Registry repos", "success")
                return "\n".join(result_lines) if result_lines else "No Artifact Registry repos found"
            return "No output"
        except Exception as e:
            return f"GCP Artifact Registry enum failed: {e}"

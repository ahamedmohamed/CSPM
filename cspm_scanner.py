import boto3
import json

# Initialize the compliance report structure
compliance_report = {
    "project": "Automated CSPM Scanner",
    "status": "Completed",
    "findings": []
}

def check_s3_buckets():
    """Check 1: Look for S3 buckets that might be open to the public"""
    print("[*] Auditing S3 Buckets...")
    s3_client = boto3.client('s3')
    
    try:
        response = s3_client.list_buckets()
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            
            # Check Public Access Block configuration
            try:
                pub_block = s3_client.get_public_access_block(Bucket=bucket_name)
                config = pub_block['PublicAccessBlockConfiguration']
                
                # If these are False, public access isn't fully blocked
                if not config['BlockPublicAcls'] or not config['IgnorePublicAcls']:
                    compliance_report["findings"].append({
                        "resource": f"S3 Bucket: {bucket_name}",
                        "severity": "HIGH",
                        "issue": "Public Access Block is disabled or misconfigured. Bucket could be public."
                    })
            except s3_client.exceptions.ClientError:
                # If there's no public access block config at all, it's a huge risk
                compliance_report["findings"].append({
                    "resource": f"S3 Bucket: {bucket_name}",
                    "severity": "CRITICAL",
                    "issue": "No Public Access Block configuration found. Bucket might be fully exposed!"
                })
    except Exception as e:
        print(f"Error scanning S3: {e}")

def check_iam_users():
    """Check 2: Look for IAM Users without MFA enabled"""
    print("[*] Auditing IAM Users...")
    iam_client = boto3.client('iam')
    
    try:
        users = iam_client.list_users()
        for user in users['Users']:
            username = user['UserName']
            
            # Check for Multi-Factor Authentication (MFA)
            mfa_response = iam_client.list_mfa_devices(UserName=username)
            if not mfa_response['MFADevices']:
                compliance_report["findings"].append({
                    "resource": f"IAM User: {username}",
                    "severity": "HIGH",
                    "issue": "Multi-Factor Authentication (MFA) is NOT enabled for this user."
                })
    except Exception as e:
        print(f"Error scanning IAM: {e}")

def check_security_groups():
    """Check 3: Look for Security Groups exposing SSH (22) or RDP (3389) to the whole internet"""
    print("[*] Auditing EC2 Security Groups...")
    ec2_client = boto3.client('ec2')
    
    try:
        response = ec2_client.describe_security_groups()
        for sg in response['SecurityGroups']:
            sg_id = sg['GroupId']
            sg_name = sg['GroupName']
            
            for permission in sg.get('IpPermissions', []):
                from_port = permission.get('FromPort')
                to_port = permission.get('ToPort')
                
                # Check if the rule targets SSH (22) or RDP (3389)
                if from_port in [22, 3389] or to_port in [22, 3389]:
                    for ip_range in permission.get('IpRanges', []):
                        # 0.0.0.0/0 means the entire public internet
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            compliance_report["findings"].append({
                                "resource": f"Security Group: {sg_name} ({sg_id})",
                                "severity": "CRITICAL",
                                "issue": f"Port {from_port} is completely exposed to the public internet (0.0.0.0/0)!"
                            })
    except Exception as e:
        print(f"Error scanning Security Groups: {e}")

if __name__ == "__main__":
    print("=== STARTING CLOUD SECURITY POSTURE ASSESSMENT ===")
    
    # Run our three custom compliance checks
    check_s3_buckets()
    check_iam_users()
    check_security_groups()
    
    # Save the output to a structured JSON file (The Deliverable)
    output_filename = "cspm_compliance_report.json"
    with open(output_filename, "w") as f:
        json.dump(compliance_report, f, indent=4)
        
    print(f"\n[+] Scan Complete! Results saved to: {output_filename}")
    print(f"[+] Total issues found: {len(compliance_report['findings'])}")
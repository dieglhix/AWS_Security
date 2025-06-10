import boto3
import json
import datetime
import os
import csv
from io import StringIO
from botocore.exceptions import ClientError

def get_accounts():
    try:
        org_client = boto3.client('organizations')
        accounts = []
        paginator = org_client.get_paginator('list_accounts')
        
        for page in paginator.paginate():
            for account in page['Accounts']:
                if account['Status'] == 'ACTIVE':
                    accounts.append({
                        'Id': account['Id'],
                        'Name': account['Name']
                    })
        return accounts
    except Exception as e:
        print(f"Error obteniendo cuentas: {str(e)}")
        raise

def check_bucket_acl(s3_client, bucket_name):
    """Check bucket ACL for public access permissions"""
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        
        public_read = False
        public_write = False
        
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            permission = grant.get('Permission', '')
            
            # Check for public access (AllUsers or AuthenticatedUsers)
            if grantee.get('Type') == 'Group':
                uri = grantee.get('URI', '')
                if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                    if permission in ['READ', 'FULL_CONTROL']:
                        public_read = True
                    if permission in ['WRITE', 'WRITE_ACP', 'FULL_CONTROL']:
                        public_write = True
        
        return public_read, public_write
    except ClientError as e:
        print(f"Error checking ACL for bucket {bucket_name}: {str(e)}")
        return None, None

def check_bucket_policy(s3_client, bucket_name):
    """Check bucket policy for public access"""
    try:
        policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy = json.loads(policy_response['Policy'])
        
        has_public_policy = False
        
        for statement in policy.get('Statement', []):
            # Check if statement allows public access
            principal = statement.get('Principal', {})
            effect = statement.get('Effect', '')
            
            if effect == 'Allow':
                # Check for wildcard principal
                if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                    has_public_policy = True
                    break
                # Check for public principal in list format
                elif isinstance(principal, dict) and isinstance(principal.get('AWS'), list):
                    if '*' in principal.get('AWS', []):
                        has_public_policy = True
                        break
        
        return has_public_policy
    except ClientError as e:
        # NoSuchBucketPolicy is expected for buckets without policies
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            return False
        print(f"Error checking policy for bucket {bucket_name}: {str(e)}")
        return None

def check_bucket_security(account_id, account_name, bucket_name, sts_client):
    try:
        # Asumir rol en la cuenta destino
        role_arn = f'arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole'
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='S3AuditSession'
        )
        
        # Crear cliente S3 con credenciales asumidas
        s3_client = boto3.client(
            's3',
            aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
            aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
            aws_session_token=assumed_role['Credentials']['SessionToken']
        )
        
        # Obtener configuración de acceso público (Block Public Access)
        try:
            public_access = s3_client.get_public_access_block(Bucket=bucket_name)
            pab_config = public_access['PublicAccessBlockConfiguration']
            
            block_public_acls = pab_config.get('BlockPublicAcls', False)
            ignore_public_acls = pab_config.get('IgnorePublicAcls', False)
            block_public_policy = pab_config.get('BlockPublicPolicy', False)
            restrict_public_buckets = pab_config.get('RestrictPublicBuckets', False)
        except ClientError:
            # If no public access block is configured, all settings default to False
            block_public_acls = False
            ignore_public_acls = False
            block_public_policy = False
            restrict_public_buckets = False
        
        # Check unholy trinity
        public_read_acl, public_write_acl = check_bucket_acl(s3_client, bucket_name)
        public_policy = check_bucket_policy(s3_client, bucket_name)
        
        # Determine overall public access status
        is_public = False
        if not block_public_acls or not block_public_policy or not ignore_public_acls or not restrict_public_buckets:
            is_public = True
        
        # Additional check: if any of the unholy trinity is true, bucket is potentially public
        if public_read_acl or public_write_acl or public_policy:
            is_public = True
        
        bucket_arn = f'arn:aws:s3:::{bucket_name}'
        
        return {
            'AccountId': account_id,
            'AccountName': account_name,
            'BucketName': bucket_name,
            'BucketARN': bucket_arn,
            'IsPublic': is_public,
            'BlockPublicAcls': block_public_acls,
            'IgnorePublicAcls': ignore_public_acls,
            'BlockPublicPolicy': block_public_policy,
            'RestrictPublicBuckets': restrict_public_buckets,
            'PublicReadACL': public_read_acl if public_read_acl is not None else 'Error',
            'PublicWriteACL': public_write_acl if public_write_acl is not None else 'Error',
            'PublicPolicy': public_policy if public_policy is not None else 'Error',
            'UnholyTrinityViolations': sum([
                1 for x in [public_read_acl, public_write_acl, public_policy] 
                if x is True
            ])
        }
    except ClientError as e:
        print(f"Error verificando bucket {bucket_name} en cuenta {account_id}: {str(e)}")
        return {
            'AccountId': account_id,
            'AccountName': account_name,
            'BucketName': bucket_name,
            'BucketARN': f'arn:aws:s3:::{bucket_name}',
            'IsPublic': 'Error',
            'BlockPublicAcls': 'Error',
            'IgnorePublicAcls': 'Error',
            'BlockPublicPolicy': 'Error',
            'RestrictPublicBuckets': 'Error',
            'PublicReadACL': 'Error',
            'PublicWriteACL': 'Error',
            'PublicPolicy': 'Error',
            'UnholyTrinityViolations': 'Error',
            'Error': str(e)
        }

def lambda_handler(event, context):
    try:
        # Inicializar clientes
        sts_client = boto3.client('sts')
        s3_client = boto3.client('s3')
        
        # Obtener todas las cuentas
        accounts = get_accounts()
        results = []
        
        # Revisar cada cuenta
        for account in accounts:
            try:
                print(f"Procesando cuenta: {account['Name']} ({account['Id']})")
                # Asumir rol en la cuenta destino
                role_arn = f'arn:aws:iam::{account["Id"]}:role/OrganizationAccountAccessRole'
                assumed_role = sts_client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName='S3AuditSession'
                )
                
                # Crear cliente S3 con credenciales asumidas
                account_s3_client = boto3.client(
                    's3',
                    aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
                    aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
                    aws_session_token=assumed_role['Credentials']['SessionToken']
                )
                
                # Listar buckets de la cuenta
                buckets = account_s3_client.list_buckets()
                
                # Revisar cada bucket
                for bucket in buckets['Buckets']:
                    result = check_bucket_security(
                        account['Id'],
                        account['Name'],
                        bucket['Name'],
                        sts_client
                    )
                    results.append(result)
            except ClientError as e:
                print(f"Error accediendo a la cuenta {account['Id']}: {str(e)}")
        
        # Crear CSV con nuevas columnas
        fieldnames = [
            'AccountId', 'AccountName', 'BucketName', 'BucketARN', 'IsPublic',
            'BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets',
            'PublicReadACL', 'PublicWriteACL', 'PublicPolicy', 'UnholyTrinityViolations',
            'Error'
        ]
        
        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
        
        # Guardar el reporte en S3
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        report_key = f"{os.environ['REPORT_PREFIX']}s3_security_audit_report_{timestamp}.csv"
        
        s3_client.put_object(
            Bucket=os.environ['REPORT_BUCKET'],
            Key=report_key,
            Body=output.getvalue()
        )
        
        # Count violations for summary
        total_buckets = len([r for r in results if r.get('Error') is None])
        unholy_trinity_violations = len([r for r in results if r.get('UnholyTrinityViolations', 0) > 0])
        public_buckets = len([r for r in results if r.get('IsPublic') is True])
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Reporte de seguridad S3 generado exitosamente',
                'reportLocation': f"s3://{os.environ['REPORT_BUCKET']}/{report_key}",
                'summary': {
                    'totalBuckets': total_buckets,
                    'publicBuckets': public_buckets,
                    'unholyTrinityViolations': unholy_trinity_violations
                }
            })
        }
    except Exception as e:
        print(f"Error en la ejecución de la función: {str(e)}")
        raise
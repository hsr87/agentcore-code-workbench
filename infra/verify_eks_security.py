"""Verify deployed EKS/AgentCore storage and container security without reading credentials.

Run while a demo session Pod exists for the container/metadata checks.
"""
import argparse,json,pathlib,subprocess,os,shlex
import boto3
parser=argparse.ArgumentParser(description="Read-only deployment security checks; requires AWS describe and Kubernetes read/exec permissions.")
parser.add_argument('--cluster-name', help='Required when kube context is an alias and CWE_EKS_CLUSTER_NAME is unset')
parser.add_argument('--env-file',type=pathlib.Path,default=pathlib.Path('.env.eks'))
parser.add_argument('--output',type=pathlib.Path,default=pathlib.Path('.cwe_data/deployment/security-report.json'))
args=parser.parse_args()
for line in args.env_file.read_text().splitlines():
 if not line.strip() or line.lstrip().startswith('#'): continue
 key,sep,value=line.partition('=')
 key=key.strip()
 # Project settings only: never import credentials parked in the file.
 if sep and (key.startswith('CWE_') or key in ('AWS_REGION','KUBECONFIG')):
  parsed=shlex.split(value,comments=True)
  os.environ[key]=parsed[0] if parsed else ''
region=os.environ.get('AWS_REGION','us-east-1')
context=os.environ['CWE_EKS_CONTEXT']
namespace=os.environ.get('CWE_EKS_NAMESPACE','cwe')
cluster=args.cluster_name or os.environ.get('CWE_EKS_CLUSTER_NAME') or context.rsplit('/',1)[-1]
kube=['kubectl','--context',context]
def get(*args):return json.loads(subprocess.check_output([*kube,*args,'-o','json']))
checks={}
eks=boto3.client('eks',region_name=region).describe_cluster(name=cluster)['cluster']
vpc=eks['resourcesVpcConfig']
checks['eks_api_not_world_open']=(not vpc.get('endpointPublicAccess')) or '0.0.0.0/0' not in vpc.get('publicAccessCidrs',[])
checks['eks_private_endpoint_enabled']=vpc['endpointPrivateAccess']
checks['eks_secrets_encrypted']=any('secrets' in e.get('resources',[]) for e in eks.get('encryptionConfig',[]))
checks['eks_audit_logging_enabled']=any(s['enabled'] and 'audit' in s['types'] for s in eks.get('logging',{}).get('clusterLogging',[]))
nodes=get('get','nodes')['items']
ids=[n['spec']['providerID'].rsplit('/',1)[-1] for n in nodes]
c=boto3.client('ec2',region_name=region)
instances=[i for r in c.describe_instances(InstanceIds=ids)['Reservations'] for i in r['Instances']]
checks['imdsv2_required']=all(i['MetadataOptions']['HttpTokens']=='required' for i in instances)
checks['metadata_hop_limit_one']=all(i['MetadataOptions']['HttpPutResponseHopLimit']==1 for i in instances)
android_ids={n['spec']['providerID'].rsplit('/',1)[-1] for n in nodes if n['metadata']['labels'].get('cwe/workload')=='android'}
checks['nested_virtualization_enabled']=bool(android_ids) and all(i['CpuOptions'].get('NestedVirtualization')=='enabled' for i in instances if i['InstanceId'] in android_ids)
groups={g['GroupId'] for i in instances for g in i['SecurityGroups']}
sgs=c.describe_security_groups(GroupIds=list(groups))['SecurityGroups']
def world_open(p):
 return (any(r.get('CidrIp')=='0.0.0.0/0' for r in p.get('IpRanges',[]))
  or any(r.get('CidrIpv6')=='::/0' for r in p.get('Ipv6Ranges',[]))
  or bool(p.get('PrefixListIds')))
checks['nodes_no_world_open_ingress']=not any(world_open(p) for g in sgs for p in g['IpPermissions'])
s3=boto3.client('s3',region_name=region)
bucket=os.environ['CWE_STORAGE_URI'].removeprefix('s3://').split('/')[0]
checks['s3_public_access_blocked']=all(s3.get_public_access_block(Bucket=bucket)['PublicAccessBlockConfiguration'].values())
checks['s3_versioning']=s3.get_bucket_versioning(Bucket=bucket)['Status']=='Enabled'
checks['s3_encryption']=bool(s3.get_bucket_encryption(Bucket=bucket)['ServerSideEncryptionConfiguration']['Rules'])
pods=get('-n',namespace,'get','pods','-l','app.kubernetes.io/name=cwe-android')['items']
if pods:
 p=pods[0]['spec']
 checks['session_sa_token_disabled']=not p['automountServiceAccountToken']
 sec=[x.get('securityContext',{}) for x in p['containers']]
 checks['session_containers_nonprivileged']=all(not x.get('privileged',False) for x in sec)
 checks['session_no_privilege_escalation']=all(x.get('allowPrivilegeEscalation') is False for x in sec)
 checks['session_all_capabilities_dropped']=all(x.get('capabilities',{}).get('drop')==['ALL'] for x in sec)
 checks['session_no_hostpath']=all('hostPath' not in v for v in p['volumes'])
 checks['session_no_host_namespaces']=not (p.get('hostNetwork') or p.get('hostPID') or p.get('hostIPC'))
 checks['agent_and_builder_non_root']=all(x.get('securityContext',{}).get('runAsNonRoot') is True
  for x in p['containers'] if x['name'] in ('device-agent','builder'))
 policies={i['metadata']['name'] for i in get('-n',namespace,'get','networkpolicies')['items']}
 checks['network_policies_present']={'cwe-default-deny','cwe-device'} <= policies
 checks['builder_no_token_env']=all(e['name']!='DEVICE_AGENT_TOKEN' for x in p['containers'] if x['name']=='builder' for e in x.get('env',[]))
 command=[*kube,'-n',namespace,'exec',pods[0]['metadata']['name'],'-c','builder','--','python3','-c',
 "import urllib.request; urllib.request.urlopen('http://169.254.169.254/latest/meta-data/',timeout=3)"]
 r=subprocess.run(command,capture_output=True,text=True,timeout=15)
 checks['builder_metadata_network_blocked']=r.returncode!=0 and ('timed out' in r.stderr or 'unreachable' in r.stderr)
report={'passed':all(checks.values()),'checks':checks,'pod_checked':bool(pods)}
args.output.parent.mkdir(parents=True,exist_ok=True)
args.output.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
raise SystemExit(0 if report['passed'] else 1)

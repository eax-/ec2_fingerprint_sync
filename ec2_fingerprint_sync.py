import boto3, os
import pathlib

algo_preference = ["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"]
fp_tag_name = "fingerprint"

ec2 = boto3.resource('ec2')
s3 = boto3.resource('s3')

def get_fingerprint(logs):
    logs = logs['Output'].split("\r\n")
    fps = filter(lambda line: any(line.startswith(text + " ") for text in algo_preference), logs)
    # select the best algorithm according to algo_preference
    fps = sorted(fps, key = lambda x: algo_preference.index(x.split(' ')[0]))[0]
    if not fps:
        raise ValueError("invalid fingerprint")
    return fps

def tag_instances_with_fps():
    instances = ec2.instances.filter(
        Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    instances = filter(lambda x: fp_tag_name not in [t['Key'] for t in x.tags], instances)
    for instance in instances:
        try:
            print("setting fingerprint tag on instance", instance.id, "... ", end = '')
            fingerprint = get_fingerprint(instance.console_output())
            ec2.create_tags(Resources = [instance.id], Tags=[{'Key':fp_tag_name, 'Value': fingerprint}])
            print("done")
        except Exception as ex:
            print("failed:", ex)

def instance_id_to_dns(instance_id):
    return ec2.Instance(instance_id).public_dns_name

def tag_by_key(tags, key):
    return next(filter(lambda x: x['Key'] == key, tags))['Value']

def get_fingerprints_from_aws():
    instances = ec2.instances.filter(
            Filters=[{'Name': 'tag-key', 'Values': [fp_tag_name]}])
    return {instance.public_dns_name: tag_by_key(instance.tags, fp_tag_name) for instance in instances}

def get_dns_from_knownhosts(lines):
    return set(line.split(' ', 1)[0] for line in lines)

def sync_known_hosts():
    with open(pathlib.PurePath(pathlib.Path.home(), ".ssh", "known_hosts"), "a+") as f:
        f.seek(0, os.SEEK_SET)
        known_hosts = f.readlines()
        already_known = get_dns_from_knownhosts(known_hosts)
        fps_to_add = list(filter(lambda x: x[0] and x[0] not in already_known, get_fingerprints_from_aws().items()))
        if fps_to_add:
            print("adding to ~/.ssh/known_hosts:\n", "\n".join(" " + fp[0] for fp in fps_to_add), sep = "")
            f.seek(0, os.SEEK_END)
            f.write("\n".join(fp[0] + " " + fp[1] for fp in fps_to_add))

tag_instances_with_fps()
sync_known_hosts()

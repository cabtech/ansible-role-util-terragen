#!/usr/bin/env python3
"""Pulls information from Vultr to Ansible"""
# pylint: disable-msg=line-too-long
# pylint: disable-msg=too-many-lines
# pylint: disable-msg=useless-return
# pylint: disable-msg=redefined-outer-name
# pylint: disable-msg=too-many-branches
# pylint: disable-msg=too-many-locals
# pylint: disable-msg=too-many-arguments
# pylint: disable-msg=too-many-nested-blocks
# pylint: disable-msg=too-many-statements

import sys
import os
import json
import time
import re
import requests
import boto3

# --------------------------------

TERRAGEN_ENVVARS = ["TERRAGEN_ENV_NAME", "TERRAGEN_PRODUCT_NAME"]
TERRAGEN_AWS_ENVVARS = ["TERRAGEN_AWS_ACCT", "TERRAGEN_AWS_REGION"]

AWS_ENVVARS = [
    ["AWS_SHARED_CREDENTIALS_FILE"],
    ["AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID"],
]
DOCEAN_ENVVARS = ["WIBBLE"]
LINODE_ENVVARS = ["WIBBLE"]
VULTR_ENVVARS = ["VULTR_API_KEY"]

# --------------------------------
# static vars

AWS_GEOG = {
    "central": "ce",
    "east": "ea",
    "north": "no",
    "northeast": "ne",
    "northwest": "nw",
    "south": "so",
    "southeast": "se",
    "southwest": "sw",
    "west": "we",
}

# groups we compare hostnames against
HOST_GROUPS = [
    "bastion",
    "build",
    "bycon",
    "bywork",
    "consul",
    "envoy",
    "grafana",
    "hashi",
    "misc",
    "mirror",
    "nomad",
    "postgres",
    "quest",
    "svc",
    "vault",
    "vpn",
    "zoo",
]

PORTS = {"consul": 8600, "kafka": 9092, "zookeeper": 2181}

ROLES = [
    "bastion",
    "boundary",
    "build",
    "consul",
    "envoy",
    "grafana",
    "hashi",
    "internet",
    "misc",
    "mirror",
    "nomad",
    "postgres",
    "quest",
    "sui",
    "svc",
    "vault",
    "vpn",
]

# servers that live in clusters
SERVER_GROUPS = ("consul", "nomad", "vault", "zoo")

# --------------------------------
# static functions


def get_groups(tags: list) -> str:
    """
    tag:AnsibleGroups allows us to override the inventory group
    returns a CSV
    """
    for tag in tags:
        if tag["Key"] == "AnsibleGroups":
            return tag["Value"]
    return None


def should_be_ignored(tags) -> bool:
    """tag:AnsibleIgnore allows us to skip a host"""
    for tag in tags:
        if tag["Key"] == "AnsibleIgnore":
            return True
    return False


def aws_get_zone(instance: object) -> tuple:
    """get the zone and zone6 from an instance"""
    zone = None
    zone6 = None
    if instance:
        try:
            zone = instance["Placement"]["AvailabilityZone"]
            fields = zone.split("-")
            if len(fields) == 3:
                zone6 = fields[0][0:2] + fields[1][0:2] + fields[2]
        except (IndexError, KeyError):
            pass
    return (zone, zone6)


def match_instance_name(
    name: str, acct: str, product: str, region5: str, role: str
) -> object:
    """need to handle multiple hostname patterns"""
    pattern = r"%s-%s-%s-%s\d*" % (acct, product, region5, role)
    # print(f'{name} vs {pattern}')  # TRACE
    return re.match(pattern, name)


def check_instance(instance: object) -> tuple:
    """pull some AWS instance data out"""
    status = instance["State"]["Name"]
    try:
        pri_ip = instance["PrivateIpAddress"]
    except KeyError:
        pri_ip = None
    try:
        pub_ip = instance["PublicIpAddress"]
    except KeyError:
        pub_ip = None
    try:
        tags = instance["Tags"]
    except KeyError:
        tags = {}
    return (status, pri_ip, pub_ip, tags)


def get_name(tags: list) -> str:
    """tag:AnsibleName allows us to override the inventory name"""
    for tag in tags:
        if tag["Key"] == "AnsibleName":
            return tag["Value"]
    for tag in tags:
        if tag["Key"] == "Name":
            return tag["Value"]
    return None


def get_aws_region5(region: str) -> str:
    """derive region5 from region"""
    fields = region.split("-")
    if len(fields) == 3:
        return fields[0][0:2] + AWS_GEOG.get(fields[1], "xx") + fields[2]
    return None


def write_to_file(fname: str, data: object) -> None:
    """add a docstring"""
    with open(fname, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(data))
        handle.close()
    return


def load_from_file(fname: str, max_age: int = 60) -> dict:
    """if the file is older than max_age seconds, return None to force a refresh"""
    try:
        if time.time() - os.stat(fname).st_mtime > max_age:
            return None
    except FileNotFoundError:
        return None
    try:
        with open(fname, "r", encoding="utf-8") as handle:
            data = json.load(handle)
            handle.close()
    except IOError:
        return None
    return data


# --------------------------------


class Inventory:
    def __init__(self):
        self.data = {}
        self.instances = []
        self.product = None

        meta = {}
        meta["hostvars"] = {}
        meta["hostvars"]["localhost"] = {}
        meta["hostvars"]["localhost"]["ansible_connection"] = "local"
        uber = {}
        uber["children"] = []
        uber["hosts"] = []
        uber["vars"] = {}
        uber["vars"]["boundary_servers"] = []
        uber["vars"]["consul_servers"] = []
        uber["vars"]["nomad_servers"] = []
        uber["vars"]["vault_servers"] = []
        ungrouped = {}
        ungrouped["children"] = []
        ungrouped["hosts"] = ["localhost"]
        ungrouped["vars"] = {}
        full = {}
        full["children"] = ["uber", "ungrouped"]
        full["hosts"] = []
        full["vars"] = {}

        # reply["_errors"] = errors
        self.data["_meta"] = meta
        self.data["all"] = full
        self.data["uber"] = uber
        self.data["ungrouped"] = ungrouped

    def __str__(self):
        return json.dumps(self.data, sort_keys=True, indent=4)

    def add_group(self, group):
        self.data.setdefault(group, {})
        self.data[group].setdefault("children", [])
        self.data[group].setdefault("hosts", [])
        self.data[group].setdefault("vars", {})
        return

    def add_group_to_parent(self, group, parent):
        self.add_group(parent)
        self.add_group(group)
        children = self.data[parent]["children"]
        if group not in children:
            children.append(group)
        return

    def add_group_var(self, group, key, value):
        self.data[group]["vars"][key] = value
        return

    def append_item_to_group_var(self, group, key, value):
        self.data[group]["vars"][key].append(value)
        return

    def add_host(self, host):
        if host not in self.data["all"]["hosts"]:
            self.data["all"]["hosts"].append(host)
        if host not in self.data["_meta"]["hostvars"]:
            self.data["_meta"]["hostvars"][host] = {}
        return

    def get_host_var(self, host, key):
        base = self.data["_meta"]["hostvars"]
        try:
            return base[host][key]
        except KeyError:
            return None

    def add_host_var(
        self, host: str, key: str, value: str, use_in_datadog: bool = False
    ):
        base = self.data["_meta"]["hostvars"]
        base.setdefault(host, {})
        base[host][key] = value
        return

    def add_host_to_group(self, host, group):
        self.add_host(host)
        self.add_group(group)
        hosts = self.data[group]["hosts"]
        if host not in hosts:
            hosts.append(host)
        return

    def get_product(self) -> str:
        return self.product

    def set_product(self, product: str) -> str:
        self.product = product
        return self.product


# --------------------------------


class AwsCloud:
    def __init__(self):
        self.acct = os.environ["TERRAGEN_AWS_ACCT"]
        self.domain = "domain_hardcoded"
        self.instances = []
        self.product = os.environ["TERRAGEN_PRODUCT_NAME"]
        self.region = os.environ["TERRAGEN_AWS_REGION"]
        self.region5 = get_aws_region5(self.region)

    def describe_instances(self, client: object) -> list:
        """returns a list of ec2 instances filtered by tag:Product"""
        instances = []
        xargs = {"Filters": [{"Name": "tag:Product", "Values": [self.product]}]}
        reply = client.describe_instances(**xargs)
        for reservation in reply["Reservations"]:
            for instance in reservation["Instances"]:
                instances.append(instance)
        return instances

    def get_instances(self) -> list:
        """tries to load instance details from cache if not, pulls from AWS"""
        cache_file = f"/tmp/inventory-aws-{self.acct}-{self.product}-{self.region5}.json"
        self.instances = load_from_file(cache_file)
        if self.instances:
            return self.instances

        client = boto3.client("ec2", region_name=self.region)
        instances = self.describe_instances(client)
        # ditch fields that cannot be serialised
        for instance in instances:
            del instance["BlockDeviceMappings"]
            del instance["LaunchTime"]
            for iface in instance["NetworkInterfaces"]:
                del iface["Attachment"]
            del instance["UsageOperationUpdateTime"]
            instance["SortByThis"] = get_name(instance.get("Tags", "zzz"))
        sorted_instances = sorted(instances, key=lambda item: item["SortByThis"])
        write_to_file(cache_file, sorted_instances)
        self.instances = sorted_instances
        return self.instances

    def categorise(self, inv: Inventory) -> None:
        """sort through the AWS instances"""
        inv.add_group("aws")
        inv.add_group_to_parent("uber", "aws")
        # add_group_var(inventory, "uber", "consul_datacentre", f"{self.region5}-{product}-{acct}")
        # add_group_var(inventory, "aws", "dnsmasq_domains", [f"{region}.compute.internal"])
        # add_group_var(inventory, "aws", "dnsmasq_ok_to_reboot", True)

        ipv4_private = []

        # find the bastion hosts first
        role = "bastion"
        for instance in self.instances:
            (status, pri_ip, pub_ip, tags) = check_instance(instance)
            if status != "running":
                continue
            if pri_ip is None:
                continue
            if pub_ip is None:
                continue

            name = get_name(tags)
            if name is None:
                continue
            ipv4_private.append(pri_ip)

            matched = match_instance_name(name, self.acct, self.product, self.region5, role)
            if matched:
                # pylint: disable-msg=unused-variable
                (zone, zone6) = aws_get_zone(instance)
                # pylint: enable-msg=unused-variable
                inv.add_host(name)
                inv.add_host_to_group(name, role)
                inv.add_host_to_group(name, "internet")
                inv.add_host_var(name, "acct", self.acct, use_in_datadog=True)
                inv.add_host_var(name, "cloud", "aws", use_in_datadog=True)
                inv.add_host_var(name, "ct_cloud", "aws")
                inv.add_host_var(name, "function", role, use_in_datadog=True)
                inv.add_host_var(name, "ip_pri", pri_ip)
                inv.add_host_var(name, "ip_pub", pub_ip)
                inv.add_host_var(name, "product", self.product, use_in_datadog=True)
                inv.add_host_var(name, "region", self.region5, use_in_datadog=True)
                inv.add_host_var(name, "region_name", self.region)  # full region name
                inv.add_host_var(name, "zone", zone6, use_in_datadog=True)
        # endfor instances

        have_default_nameserver = False

        # handle all the other instances
        for instance in self.instances:
            (status, pri_ip, pub_ip, tags) = check_instance(instance)
            if status != "running":
                continue
            if pri_ip is None:
                continue
            if should_be_ignored(tags):
                continue

            if not have_default_nameserver:
                have_default_nameserver = True
                fields = pri_ip.split(".")
                ns_cidr = ".".join((fields[0], fields[1], "0.2"))  # e.g. 10.11.0.2
                ns_cidr = "169.254.169.253"  # TODO sort out what has changed
                inv.add_group_var("aws", "dnsmasq_nameserver", ns_cidr)

            name = get_name(tags)
            if name is None:
                continue

            inv.add_host(name)
            inv.add_host_to_group(name, "aws")
            if "bastion" in name:
                continue

            ipv4_private.append(pri_ip)
            (zone, zone6) = aws_get_zone(instance)

            # see if we have defined the group(s) for this instance
            # otherwise try and work it out
            group_tags = get_groups(tags)
            if group_tags is None:
                for role in HOST_GROUPS:
                    if role != "bastion":
                        # print(f'trying to match {name} to {role}')  # TRACE
                        matched = match_instance_name(
                            name, self.acct, self.product, self.region5, role
                        )
                        if matched:
                            # print(f'matched {name} to {role}')  # TRACE
                            group_tags = role
                            break

            if group_tags is None:
                inv.add_host(name)
                inv.add_host_to_group(name, "ungrouped")
                inv.add_host_var(name, "function", "None", use_in_datadog=True)
                inv.add_group_var("ungrouped", name, "unmatched")
            else:
                groups = group_tags.split(",")
                for group in groups:
                    if group not in HOST_GROUPS:
                        function = group
                        group = "ungrouped"
                    else:
                        function = group
                    inv.add_host(name)
                    inv.add_host_to_group(name, group)
                    inv.add_host_var(name, "function", function, use_in_datadog=True)
                    if group in SERVER_GROUPS:
                        inv.append_item_to_group_var("uber", group + "_servers", pri_ip)
                    if group == "bycon":
                        inv.append_item_to_group_var("uber", "boundary_servers", pri_ip)
                    elif group == "consul":
                        inv.add_group_var(
                            "aws", "dnsmasq_consul_port", PORTS["consul"]
                        )  # only set if we find a consul host

            if pub_ip is not None:
                inv.add_host_to_group(name, "internet")
                fields = name.split("-")
                fields.reverse()
                subdomain = "-".join(fields)
                inv.add_host_var(name, "subdomain", subdomain)
                inv.add_host_var(name, "fqdn", ".".join((subdomain, self.domain)))
                subdomain = "-".join(fields[1:])
                inv.add_host_var(name, "domainstub", ".".join((subdomain, self.domain)))

            inv.add_host_var(name, "acct", self.acct, use_in_datadog=True)
            inv.add_host_var(name, "cloud", "aws", use_in_datadog=True)
            inv.add_host_var(name, "ct_cloud", "aws")
            inv.add_host_var(name, "ip_pri", pri_ip)
            inv.add_host_var(name, "ip_pub", pub_ip)
            inv.add_host_var(name, "product", self.product, use_in_datadog=True)
            inv.add_host_var(name, "region", self.region5, use_in_datadog=True)
            inv.add_host_var(name, "region_name", self.region)  # full region name
            inv.add_host_var(name, "zone", zone6, use_in_datadog=True)

            inv.add_group_var(
                "uber", "all_ipv4_private", sorted(list(set(ipv4_private)))
            )
        # endfor instances
        return

    def write_ssh_config(self, inv: Inventory) -> None:
        """dump out AWS instance details in SSH config format"""
        bastion_addr = None

        bastion_keypath = os.environ["TERRAGEN_BASTION_KEYPATH"]

        try:
            bastion_username = os.environ["TERRAGEN_BASTION_USERNAME"]
        except KeyError:
            bastion_username = "ubuntu"
        try:
            node_keypath = os.environ["TERRAGEN_NODE_KEYPATH"]
        except KeyError:
            node_keypath = bastion_keypath
        try:
            node_username = os.environ["TERRAGEN_NODE_USERNAME"]
        except KeyError:
            node_username = bastion_username

        sshcfg = f"{self.acct}-{self.product}-{self.region5}.cfg"
        handle = open(sshcfg, "w", encoding="utf-8")

        # loop through the bastions first as we need a public IP
        for instance in self.instances:
            (status, pri_ip, pub_ip, tags) = check_instance(instance)
            if status != "running":
                continue
            if pri_ip is None:
                continue
            if pub_ip is None:
                continue

            name = get_name(tags)
            if name is not None:
                matched = match_instance_name(
                    name, self.acct, self.product, self.region5, "bastion"
                )
                if matched:
                    if bastion_addr is None:
                        bastion_addr = pub_ip
                    handle.write(f"#\nhost {name}\n")
                    handle.write("    ControlMaster auto\n")
                    handle.write("    ControlPath ~/.ssh/ansible-%%r@%%h:%%p\n")
                    handle.write("    ControlPersist 5m\n")
                    handle.write(f"    HostName {pub_ip}\n")
                    handle.write(f"    IdentityFile {bastion_keypath}\n")
                    handle.write(f"    User {bastion_username}\n")

        # other hosts
        for instance in self.instances:
            (status, pri_ip, pub_ip, tags) = check_instance(instance)
            if status != "running":
                continue
            if pri_ip is None:
                continue
            name = get_name(tags)
            if name is not None:
                for role in HOST_GROUPS:
                    if role != "bastion":
                        matched = match_instance_name(
                            name, self.acct, self.product, self.region5, role
                        )
                        if matched:
                            handle.write(f"#\nhost {name}\n")
                            handle.write(f"    IdentityFile {node_keypath}\n")
                            handle.write(
                                f"    ProxyCommand ssh -q -i {bastion_keypath} {bastion_username}@{bastion_addr} nc {pri_ip} 22\n"
                            )
                            handle.write(f"    User {node_username}\n")
                            break

        # finish the file off nicely
        handle.write("# end\n")
        handle.close()
        return


# --------------------------------


class VultrCloud:
    def __init__(self):
        self.endpoint = "https://api.vultr.com/v2"
        self.instances = []
        self.key = os.environ["VULTR_API_KEY"]

    def get_instances(self) -> list:
        endpoint = f"{self.endpoint}/instances"
        headers = {"Authorization": f"Bearer {self.key}"}
        reply = requests.get(endpoint, headers=headers, timeout=10)
        tmp = reply.json()["instances"]
        # print(json.dumps(instances))
        for instance in tmp:
            if instance["power_status"] == "running":
                del instance["kvm"]
                self.instances.append(instance)
                # print(json.dumps(instance))
        return

    def categorise(self, inv: Inventory):
        for instance in self.instances:
            label = instance.get("label", None)
            hostname = instance.get("hostname", None)
            for role in ROLES:
                if (role in hostname) or (role in label):
                    inv.add_host_to_group(hostname, role)
                    inv.add_host_to_group(hostname, "uber")
                    inv.add_host_var(hostname, "cloud", "vultr")
                    inv.add_host_var(hostname, "function", role)
                    inv.add_host_var(hostname, "ip_pub", instance.get("main_ip", None))
                    inv.add_host_var(
                        hostname, "ip_pri", instance.get("internal_ip", None)
                    )
                    inv.add_host_var(hostname, "region", instance.get("region", None))
        return

    def write_ssh_config(self, inv: Inventory) -> None:
        """dump out host details in SSH config format"""
        # TODO 3
        bastion_username = "root"
        keypath = "id_vultr"
        product = inv.get_product()
        bastion_addr = None

        fname = f"{product}_vultr.cfg"
        handle = open(fname, "w", encoding="utf-8")

        for instance in self.instances:
            hostname = instance.get("hostname", None)
            role = inv.get_host_var(hostname, "function")
            if role == "bastion":
                addr = instance.get("main_ip", None)

                handle.write(f"#\nhost {hostname}\n")
                handle.write("    ControlMaster auto\n")
                handle.write("    ControlPath ~/.ssh/ansible-%%r@%%h:%%p\n")
                handle.write("    ControlPersist 5m\n")
                handle.write(f"    HostName {addr}\n")
                handle.write(f"    IdentityFile {keypath}\n")
                handle.write(f"    User {bastion_username}\n")
                if bastion_addr is None:
                    bastion_addr = addr

        for instance in self.instances:
            hostname = instance.get("hostname", None)
            role = inv.get_host_var(hostname, "function")
            if role != "bastion":
                addr = instance.get("internal_ip", None)
                hostname = instance.get("hostname", None)

                handle.write(f"#\nhost {hostname}\n")
                # handle.write(f"    HostName {addr}\n")
                handle.write(f"    IdentityFile {keypath}\n")
                handle.write(
                    f"    ProxyCommand ssh -q -i {keypath} {bastion_username}@{bastion_addr} nc {addr} 22\n"
                )
                handle.write(f"    User {bastion_username}\n")

        handle.write("#\n# end\n")
        handle.close()
        return


# --------------------------------


def pre_flight_checks() -> (list, list):
    """Check we have the right ennvars"""

    clouds = []
    errors = []

    for env in TERRAGEN_ENVVARS:
        try:
            os.environ[env]
        except KeyError:
            errors.append(f"Could not read {env}")

    aws_is_ok = True
    for env in TERRAGEN_AWS_ENVVARS:
        try:
            os.environ[env]
        except KeyError:
            errors.append(f"Could not read {env}")
            aws_is_ok = False

    if aws_is_ok:
        for group in AWS_ENVVARS:
            aws_is_ok = True
            for env in group:
                try:
                    os.environ[env]
                except KeyError:
                    errors.append(f"Could not read {env}")
                    aws_is_ok = False
            if aws_is_ok:
                clouds.append("aws")
                break

    docean_is_ok = True
    for env in DOCEAN_ENVVARS:
        try:
            os.environ[env]
        except KeyError:
            errors.append(f"Could not read {env}")
            docean_is_ok = False
    if docean_is_ok:
        clouds.append("docean")

    vultr_is_ok = True
    for env in VULTR_ENVVARS:
        try:
            os.environ[env]
        except KeyError:
            errors.append(f"Could not read {env}")
            vultr_is_ok = False
    if vultr_is_ok:
        clouds.append("vultr")

    return clouds, errors


# --------------------------------


if __name__ == "__main__":
    CLOUDS, ERRORS = pre_flight_checks()
    # print(CLOUDS)
    # print(ERRORS)
    inv = Inventory()
    homedir = os.path.expanduser("~")
    product = os.environ["TERRAGEN_PRODUCT_NAME"]
    envname = os.environ["TERRAGEN_ENV_NAME"]
    inv.set_product(product)

    for cloud in CLOUDS:
        if cloud == "aws":
            aws = AwsCloud()
            aws.get_instances()
            aws.categorise(inv)
            aws.write_ssh_config(inv)
        elif cloud == "docean":
            pass
        elif cloud == "gcp":
            pass
        elif cloud == "linode":
            pass
        elif cloud == "vultr":
            nimbus = VultrCloud()
            nimbus.get_instances()
            nimbus.categorise(inv)
            nimbus.write_ssh_config(inv)
    print(str(inv))
    sys.exit(0)

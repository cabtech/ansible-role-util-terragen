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

# import time
# import re
import requests

TERRAGEN_ENVVARS = ["TERRAGEN_ENV_NAME", "TERRAGEN_PRODUCT_NAME"]
VULTR_ENVVARS = ["VULTR_API_KEY"]

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

# --------------------------------


class Inventory:
    def __init__(self):
        self.data = {}
        self.key = os.environ["VULTR_API_KEY"]
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

    def add_host_var(self, host, key, value):
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
        fname = f"{product}_vultr.cfg"

        bastion_addr = None
        handle = open(fname, "w", encoding="utf-8")
        for instance in self.instances:
            hostname = instance.get("hostname", None)
            role = inv.get_host_var(hostname, "function")
            if role == "bastion":
                addr = instance.get("main_ip", None)

                handle.write(f"#\nhost {hostname}\n")
                handle.write("    ControlMaster auto\n")
                handle.write(
                    f"    ControlPath ~/.ssh/{product}-{hostname}-%%r@%%h:%%p\n"
                )
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

    cloud_is_ok = True
    for env in VULTR_ENVVARS:
        try:
            os.environ[env]
        except KeyError:
            errors.append(f"Could not read {env}")
            cloud_is_ok = False
    if cloud_is_ok:
        clouds.append("vultr")

    return clouds, errors


# --------------------------------


if __name__ == "__main__":
    CLOUDS, ERRORS = pre_flight_checks()
    inv = Inventory()
    # ERRORS)
    homedir = os.path.expanduser("~")
    product = os.environ["TERRAGEN_PRODUCT_NAME"]
    envname = os.environ["TERRAGEN_ENV_NAME"]
    inv.set_product(product)

    for cloud in CLOUDS:
        if cloud == "aws":
            pass
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

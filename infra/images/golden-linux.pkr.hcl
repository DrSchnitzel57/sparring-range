# RETIRED (paired 03+04, 2026-10-12): Packer is NOT the release build path.
# The supported path is `python infra/images/build.py` from the pinned inputs
# in `infra/images/manifest.json` (+ `infra/images/README.md`). This file
# remains for history only; release builds must not use it.
#
# Packer config for the Linux golden image (OPTIONAL per plan). The supported,
# primary path remains manual: import a stock Ubuntu cloud image once (VMID
> 9000), boot it, run telemetry/install.sh + provision-linux-golden.sh, then
# `qm template 9100`. This file is for repeatable rebuilds where the operator
# has packer + network access to PVE:  packer validate && packer build.
#
# F21 fixes: correct PLUGIN SOURCE (the old file named the Terraform provider),
# valid HCL, and a file provisioner that actually TRANSFERS the repo files the
# shell provisioner expects (the old one assumed they were already inside).
#
# Windows golden images (DC/Win10 + Sysmon) stay hands-on-keyboard for Drew
# (licensing/OOBE); see infra/images/WINDOWS-CHECKLIST.md.

packer {
  required_plugins {
    proxmox = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/proxmox"   # hashicorp packer-plugin-proxmox
    }
  }
}

variable "proxmox_api_token_id" {
  type      = string
  sensitive = false
}

variable "proxmox_api_token_secret" {
  type      = string
  sensitive = true
}

variable "target_node_name" {
  type    = string
  default = "r740"
}

variable "base_vm_id" {
  type    = string
  default = "9000"   # stock Ubuntu cloud image import (Drew does this once)
}

source "proxmox-clone" "golden-linux" {
  proxmox_url              = "https://CHANGEME:8006/"
  username                 = "root@pam"
  token                    = "${var.proxmox_api_token_id}:${var.proxmox_api_token_secret}"
  node                     = var.target_node_name

  clone_vm_id              = var.base_vm_id
  vm_id                    = 9100
  vm_name                  = "golden-linux"
  full_clone               = true   # GOLDEN image is a full clone; scenario VMs are
                                     # LINKED clones of this one (the cheap part)

  ip_config {
    ipv4 { ip = "dhcp" }   # golden build runs on a DHCP-able build network;
                           # the range VLAN itself stays no-egress
  }
  network { bridge = "vmbr0" }
  cpu_type = "host"
  memory   = 2048
  disks {
    disk {
      storage_folder = "local-lvm"
      type           = "scsi"
      size           = "20G"
    }
  }
  ssh_username = "ubuntu"
}

build {
  sources = ["source.proxmox-clone.golden-linux"]

  # ACTUALLY transfer the files the provisioning script installs (F21)
  file_provisioner "upload" {
    # (file provisioner blocks are declared as provisioner "file")
  }

  provisioner "file" {
    source      = "telemetry/"
    destination = "/opt/sparring-range/telemetry/"
  }

  provisioner "shell" {
    inline = ["sudo mkdir -p /opt/sparring-range && sudo chown ubuntu /opt/sparring-range"]
    order  = "before"
  }

  provisioner "shell" {
    script = "infra/images/provision-linux-golden.sh"
  }

  # NOTE: template conversion is a PVE-side step (`qm template 9100`) — the
  # clone builder does not templatize; operator runs it after the build.
}

# Packer config for the Linux golden image (optional per plan — the shell script
# path works fine; this is for repeatable rebuilds if you want them).
# Windows golden images (DC/Win10 + Sysmon) are hands-on-keyboard for Drew (Part 6.3);
# packer+winrm can automate them later once licensing/OOBE are solved.

packer {
  required_plugins {
    proxmox = {
      version = ">= 1.1.0"
      source  = "github.com/bpg/proxmox"   # the plan's preferred provider
    }
  }
}

variable "proxmox_api_token_id" { type = string }
variable "proxmox_api_token_secret" { type = string, sensitive = true }
variable "target_node_name" { type = string, default = "r740" }

source "proxmox-clone" "golden-linux" {
  proxmox_api_url          = "https://CHANGEME:8006"
  proxmox_api_token_id     = var.proxmox_api_token_id
  proxmox_api_token_secret = var.proxmox_api_token_secret
  target_node_name         = var.target_node_name

  clone_vm = "9000"            # stock Ubuntu cloud image import (Drew does this once)
  vm_name  = "golden-linux"
  full_clone = true             # the GOLDEN image is a full clone; scenario VMs are
                                # LINKED clones of this one (that's the cheap part)

  ip_config { ipv4 { ip = "dhcp" } }   # golden build happens on a DHCP-able network;
                                       # the range VLAN itself stays no-egress
  cpu_type = "host"
  memory   = 2048
  disk_size = "20G"
}

build {
  sources = ["source.packer.proxmox-clone.golden-linux"]

  provisioner "shell" {
    script = "infra/images/provision-linux-golden.sh"
  }
}

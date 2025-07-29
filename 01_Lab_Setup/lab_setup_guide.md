# Lab Setup Guide

## Purpose

This document provides a detailed guide on how to set up the Kali Linux and Metasploitable2 VMs for the cybersecurity lab, focusing on a professional and clear approach for a beginner in the field.

## Hypervisor Used

- [] Oracle VirtualBox


## Metasploitable2 VM Setup

### Steps for importing/creating Metasploitable2 VM:

1. **Download Metasploitable2:** Obtain the Metasploitable2 VM image (usually a `.vmdk` or `.ova` file) from a trusted source like SourceForge.

1. **Import into VirtualBox:**
  - Open Oracle VirtualBox.
  - Go to `File` > `Import Appliance...` if you downloaded an `.ova` file, and follow the wizard.
  - If you downloaded a `.vmdk` file, create a new virtual machine (`New` button), select `Linux` as the type and `Ubuntu (64-bit)` as the version (Metasploitable2 is based on Ubuntu). When prompted for a hard disk, choose `Use an existing virtual hard disk file` and navigate to your downloaded `.vmdk`.

1. **Initial Configuration:** Adjust RAM (e.g., 1024 MB) and CPU settings as needed. Ensure the display memory is sufficient.

## Kali Linux VM Setup

### Steps for installing/configuring Kali Linux VM:

1. **Download Kali Linux:** Download the Kali Linux installer ISO from the official Kali Linux website.

1. **Create New VM in VirtualBox:**
  - Click `New` in VirtualBox.
  - Name your VM (e.g., `Kali-CyberLab`), select `Linux` as type and `Debian (64-bit)` as version.
  - Allocate RAM (e.g., 2048 MB or more, depending on your host system).
  - Create a virtual hard disk (VDI, dynamically allocated, e.g., 20-30 GB).

1. **Install Kali Linux:** Mount the downloaded Kali ISO to the virtual CD/DVD drive of your new VM and start the VM to begin the installation process. Follow the on-screen prompts for a standard installation.

## Network Configuration

### Isolated Internal Network Setup:

To ensure a safe and isolated lab environment, we will configure an internal network in VirtualBox.

1. **Create Internal Network:**
  - In VirtualBox, go to `File` > `Host Network Manager`.
  - Click `Create` to add a new host-only network. Note down its name (e.g., `vboxnet0`).
  - Go to `File` > `Host Network Manager` again, select the newly created network, and click `Properties`. Ensure `Configure Adapter Manually` is unchecked and `DHCP Server` is enabled. This will allow VirtualBox to assign IPs if needed, though we will set static IPs.

1. **Configure VM Network Adapters:**
    - For both Kali Linux and Metasploitable2 VMs:
      - Go to `Settings` > `Network`.
      - Adapter 1: Set `Attached to:` to `Internal Network`.
      - Select `CyberLab_Net` as the `Name` for the internal network. If it doesn't exist, type it in, and VirtualBox will create it.
      - Ensure `Promiscuous Mode` is set to `Allow All` (especially useful for Wireshark).

### Static IP Address Assignment:

Assigning static IP addresses ensures consistent connectivity within your isolated lab.

- **Kali Linux VM:** `192.168.50.10`

- **Metasploitable2 VM:** `192.168.50.11`

#### Steps for Kali Linux:

1. Open a terminal in Kali Linux.

1. Edit the network configuration file (e.g., `/etc/network/interfaces` or use NetworkManager GUI).

sudo nano /etc/network/interfaces
`3.  Add the following configuration for your network interface (e.g., `eth0` or `enp0s3`):
   `
auto eth0
iface eth0 inet static
address 192.168.50.10
netmask 255.255.255.0
gateway 192.168.50.1
`    *Note: The `gateway` IP (e.g., 192.168.50.1) is a placeholder. For an internal network without internet access, it's often not strictly necessary but good practice to include a non-routable IP within the subnet.* 
4.  Save and exit (`Ctrl+O`, `Enter`, `Ctrl+X`).
5.  Restart the networking service:
   `bash
sudo systemctl restart networking
```

#### Steps for Metasploitable2:

1. Log in to Metasploitable2 (username: `msfadmin`, password: `msfadmin`).

1. Open a terminal.

1. Edit the network configuration file:

sudo nano /etc/network/interfaces
`4.  Add the following configuration for your network interface (e.g., `eth0`):
   `
auto eth0
iface eth0 inet static
address 192.168.50.11
netmask 255.255.255.0
gateway 192.168.50.1
`5.  Save and exit.
6.  Restart the networking service:
   `bash
sudo /etc/init.d/networking restart
```

## Verification Steps

### Ping Tests:

After configuring static IPs, verify connectivity between the VMs.

```bash
# From Kali Linux terminal, ping Metasploitable2
ping 192.168.50.11

# From Metasploitable2 terminal, ping Kali Linux
ping 192.168.50.10
```

Successful pings indicate that your internal network is correctly configured.

## Challenges Encountered

Setting up a virtual lab can present several challenges, especially for those new to virtualization and networking. Here are some common issues and how a cybersecurity beginner might resolve them:

 **Network Connectivity Issues (No Ping Response):**
  - **Problem:** VMs cannot ping each other, or cannot access the internet (if intended).
    - **Resolution:**
      - **Verify Network Adapter Settings:** Double-check that both VMs are set to `Internal Network` and are using the *exact same* `Name` (e.g., `CyberLab_Net`). Ensure `Promiscuous Mode` is `Allow All`.
      - **Check IP Configuration:** Confirm static IP addresses, netmasks, and gateways are correctly set in each VM's network configuration file. A common mistake is a typo in the IP address or netmask.
      - **Firewall:** Temporarily disable firewalls (e.g., `ufw` on Kali, `iptables` on Metasploitable2) to rule them out as the cause. If disabling resolves the issue, re-enable and configure rules to allow necessary traffic.
      - **VM Restart:** After making network changes, always restart the VM or at least the networking service within the VM.

## Screenshots

- See `vm_settings_screenshots/` folder for visual documentation of VM configurations, including network adapter settings and static IP configurations.


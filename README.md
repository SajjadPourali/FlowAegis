
# flowaegis - Kernel-Level Network Traffic Control Tool (eBPF-powered)

  

**flowaegis** is an eBPF-powered network traffic control tool that leverages kernel-level controls to permit, deny, forward, and proxy egress network traffic based on customizable filters such as IP addresses, ports, user IDs, originating process directories, and more. Currently supporting TCP, the tool is under active development and will soon include support for UDP and other features.

  

**WARNING**: This tool is under active development and should be used at your own risk.

  

## Features

  

- **Kernel-Level Control:** Utilizes eBPF to enforce network traffic rules at the kernel level.

- **Allow Traffic:** Permit network traffic based on IP addresses, ports, user IDs, process directories, and more.

- **Deny Traffic:** Block unwanted traffic using flexible filtering criteria.

- **Forward Traffic:** Redirect outbound traffic to designated destinations.

- **Proxy Traffic:** Intercept and relay traffic through a SOCKS proxy.

- **Import Rules:** Load traffic control rules from a TOML configuration file.

- **Path-Based Filtering:** Allows traffic control based on the directory from which processes are launched.

- **Current TCP Support:** Initially designed for TCP traffic, with UDP support coming soon.

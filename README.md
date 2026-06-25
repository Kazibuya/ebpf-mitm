# ft_malcolm

> ARP spoofing tool, an introduction to Man in the Middle attacks.
> ⚠️ This tool is intended for educational purposes only, in a controlled environment (virtual machine). Only spoof IPs that belong to you. Unauthorized use on third-party networks is illegal.

## Overview

`ft_malcolm` listens on the network for an ARP request broadcast by a target machine asking for the source IP, then replies with a spoofed ARP reply associating that IP with the MAC address of your choice. Once sent, the target's ARP table is poisoned and the program exits.

The project has two implementations:

- **Mandatory**: pure C with raw sockets (`recvfrom` / `sendto`)
- **Bonus** *(work in progress)*: eBPF/XDP kernel program (`xdp_prog.o`) hooked via libbpf to intercept ARP requests at the driver level. The goal is to also `XDP_DROP` the legitimate reply so the target only receives the spoofed one, and add a verbose mode.

## Requirements

| | Mandatory | Bonus |
|---|---|---|
| Compiler | gcc | gcc + clang |
| OS | Linux kernel > 3.14 | Linux kernel > 5.x (XDP support) |
| Privileges | root | root |
| Dependencies | | libbpf, linux-headers |

## Build

```bash
# Mandatory part (default)
make

# Bonus part (eBPF/XDP)
make bonus

# Clean objects
make clean

# Full clean
make fclean

# Rebuild
make re
```

## Usage

```
sudo ./ft_malcolm <source_ip> <source_mac> <target_ip> <target_mac>
```

Arguments must always be provided in that order.

| Argument | Description |
|---|---|
| `source_ip` | IP address to impersonate (the one being looked up) |
| `source_mac` | MAC address to associate with that IP (the spoofed one) |
| `target_ip` | IP of the victim machine sending the ARP request |
| `target_mac` | MAC address of the victim machine |

### Example

```bash
sudo ./ft_malcolm 10.11.1.255 aa:bb:cc:dd:ee:ff 10.11.4.5 30:d0:42:e9:fc:e1
```

```
Found available interface: enp0s3
An ARP request has been broadcast...
IP address of request: 10.11.4.5
Mac address of request: 30:d0:42:e9:fc:e1
Now sending...
Sent an ARP reply...
Exiting program...
```

On the target machine, verify with:

```bash
arp -n
```

The entry for `source_ip` should now point to the spoofed MAC.

## Error handling

```bash
# Invalid IP
sudo ./ft_malcolm 10.11.11.11 aa:bb:cc:dd:ee:ff 10.11.11.1111 aa:bb:cc:dd:ee:ff
# ft_malcolm: unknown host or invalid IP address: (10.11.11.1111)

# Invalid MAC
sudo ./ft_malcolm 10.11.11.11 aa:bb:cc:dd:ee:ff 10.11.11.11 aaa:bb:cc:dd:ee:ff
# ft_malcolm: invalid mac address: (aaa:bb:cc:dd:ee:ff)
```

The program also exits cleanly on `Ctrl+C` (SIGINT), closing the socket before exiting.

## How it works

### Mandatory

1. Parses and validates the four arguments
2. Auto-detects the first active non-loopback IPv4 network interface
3. Opens a raw `AF_PACKET` socket
4. Loops on `recvfrom`, filtering for ARP requests (`oper = 1`, ethertype `0x0806`) targeting the source IP
5. On match, sends a crafted ARP reply (`oper = 2`) back to the requester with the spoofed MAC, then exits

### Bonus (eBPF/XDP) *(work in progress)*

1. Compiles `xdp_prog.c` to BPF bytecode with clang
2. At runtime, loads and attaches the XDP program to the detected interface via libbpf
3. The XDP program intercepts ARP requests in the kernel (before userspace sees them) and pushes them into a BPF ring buffer
4. Userspace reads the ring buffer via `ring_buffer__poll`, crafts the ARP reply and sends it

> **TODO**: currently the XDP program ends with `XDP_PASS`, meaning both the spoofed reply and the legitimate one reach the target. The target's ARP table may end up with the real mapping if the legitimate reply arrives last. The remaining work is to `XDP_DROP` the legitimate reply at the XDP hook level to complete the MITM poisoning, and add a verbose mode.

## File structure

```
.
├── bonus/
│   ├── arp.h        # Header (includes libbpf, t_cleanup, prototypes)
│   ├── error.c      # Error functions
│   ├── getter.c     # Argument parsing, interface detection
│   ├── main.c       # Entry point, BPF setup, ring buffer loop
│   ├── xdp_prog.c   # eBPF/XDP kernel program
│   └── xdp_types.h  # Shared struct definitions for BPF
├── mandatory/
│   ├── arp.h        # Header
│   ├── error.c      # Error functions
│   ├── getter.c     # Argument parsing, interface detection
│   ├── main.c       # Entry point, socket loop, signal handling
│   └── utils.c      # ft_strlen, ft_strlcpy, ft_memset, ft_memcpy
└── Makefile
```

## Notes

- Only one global variable is used (`g_sock` in mandatory, `g_cleanup` in bonus), as required by the subject
- The program handles `SIGINT` gracefully: BPF objects and links are properly destroyed, the socket is closed

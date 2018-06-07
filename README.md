# arpbridge

Small tool to check if your switching, monitoring and/or intrusion detection system is working correctly and does not permit or report such things as this tool is trying to do.

*This software may only be used for good, not evil.*

## Usage
~~~ {.bash}
gcc arpbridge.c -o arpbridge
./arpbridge [-i interface] [-b {bridge-mac}] {remote-mac} {gateway-mac} {remote-ip} {gateway-ip}
~~~

`arpbridge` tries to hook into the public visible communication between two entities by sending gratious ARP to both of them and acting as a man in the middle. Each entity is redirected to a virtual MAC in the middle and traffic is forwarded transparently between them.

If you are operating a network you should really be aware of this technique and install some counteractions against it. Use this tool to make sure that your effort was worth it.

## License
Copyright (C) 2018 Bernd Holzmüller

Licensed under a slightly modified GLWTPL. See [this LICENSE](./LICENSE) for details.
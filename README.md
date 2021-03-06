# IPsec-StateMachineExtractor
This tool extracts the state machine of an IKEv1/IKEv2 implementation.

## Dependencies and Requirements
Java 1.8 or greater is required to compile/run.

Sending and receiving ESP and AH packets is done using [RockSaw v1.1.0](https://github.com/mlaccetti/rocksaw/tree/a53355067e3e2d29c87088359997b280ac3acd0b). This project comes with a binary [librocksaw.so](src/main/resources/lib/librocksaw.so) for Linux x86_64. If you are running a different architecture, you need to compile RockSaw yourself.

Under Linux, RockSaw requires the `CAP_NET_RAW` capability. This can be achieved using 

```
# setcap cap_net_raw+ep /path/to/your/java
```

## Acknowledgement
Parts of this software are funded by the Cisco University Research Program Fund through the Silicon Valley Community Foundation.

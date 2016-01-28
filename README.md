wicap
=====

Remote packet capture server for Linux that streams libpcap-compatible output to clients or (optionally) to stdout.

## Server usage
Build using the makefile and run the output as root. The server listens on TCP 40000 by default.

This binary can also be used for doing live packet captures from a rooted Android device.

## Examples of client usage
To save a remote capture to a file: 
  
    nc remote-host 40000 > capture.cap

To save a local capture: 

    wicap -o > capture.cap

To open a remote capture live in Wireshark: 

    nc remote-host 40000 | wireshark -k -i -

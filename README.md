wicap
=====

Remote packet capture server for Linux that streams libpcap-compatible output to clients.

## Server usage
Build using the makefile and run the output as root. The server listens on TCP 40000.

## Examples of client usage
Save capture to a file: nc remote-host 40000 > capture.cap

Open the capture live in Wireshark: wireshark -k -i <(nc remote-host 40000)

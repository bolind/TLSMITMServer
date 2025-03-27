# TLSMITMServer
Simple Python based man-in-the-middle server for debugging TLS connections

If the `--keylogfile` option is used, the TLS session keys will be stored to file. These can be used to decrypt a wireshark capture of the same traffic.

Note that, on certain systems, you need root privileges to listen to a port below 1024, i.e. 443.

The certificate is self-signed and very dummy, and some clients might balk at that. Also, certificate checking from MITM to the real server has been turned off.

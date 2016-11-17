# socks5_server.py
A socks5 server imepletation
## Work in most cases
This program covers most of the specs in 
[RFC 1928 SOCKS Protocol Version 5 - IETF](https://www.ietf.org/rfc/rfc1928.txt). 

**HOWEVER**, there are still some specifics are not supported yet. 
- udp associate
- bind commands 
- username/password

And there is no plan for that right now. 
For I don't need my socks5 server with udp or bind support for most of the cases. 

If you want to help adding the featuers, and like to contribute your code, I would love to merge it into this repository. 

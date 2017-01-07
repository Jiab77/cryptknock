# cryptknock
Forked from sourceforge

> This code is OLD. But might be useful for learning purposes with regards to libpcap, network programming, and openssl library functions.
>
> -- Joe Walko

## Description

Cryptknock is an encrypted port knocking tool. Unlike other port knockers which use TCP ports or other protocol information to signal the knock, an encrypted string is used as the knock. This makes it extremely difficult for an evesdropper to recover your knock (unlike other port knockers where tcpdump can be used to discover a port knock).

Encryption of the knock string is performed with RC4 using a secret key derived from a Diffie-Hellman key agreement. The entire process takes 3 UDP packets. Data is read using libpcap, so no UDP or TCP ports need to be in a listening state for the program to work.  A simple diagram can be found [here](http://cryptknock.sourceforge.net/cryptknock.jpg). A client (cryptknock.c) and a server (cryptknockd.c) are provided. More details can be found in the `INFO.md`. (Original text [here](http://cryptknock.sourceforge.net/README.txt))

## Usage

This program was designed to be lightweight and easy to use. By design, there are few options, and no messy configuration files.

The client is used as follows:
Cryptknock Options:

```shell
-t      Target server IP address
-s      Source port of outgoing UDP packet
-d      Destination port of outgoing UDP packet

$ cryptknock -t [host] -s [source port] -d [dest port]
```

The program will then prompt you for a password, at which time you can supply either the "open ports" password (to open up all TCP ports for the client's IP only) or the "close all my ports" password, which will re-firewall all your TCP ports after you're done using the server.

The server is used as follows:
Cryptknockd Options:

```shell
-i      Interface to watch for cryptknock clients
-s      Expected source port of incoming UDP packet
-d      Expected destination port of incoming UDP packet

$ sudo cryptknockd -i [iface] -s [source port] -d [dest port]
```

When the server starts, it firewalls all TCP ports using iptables. Remember, the client and server's source and destination UDP ports must agree. The `open ports` and `close ports` passwords can be set as `#defines` in the `cryptknockd.c` file. The daemon records successful and failed knocks via syslog.

## Last update

Updated 6/18/04.

## Download

The current version is [cryptknock-1.0.2.tar.gz](http://cryptknock.sourceforge.net/cryptknock-1.0.2.tar.gz) and hosted on [sourceforge](http://cryptknock.sourceforge.net)

You'll find a backup of the version on [sourceforge](http://cryptknock.sourceforge.net) in the `src` folder.

## Notes

I'm not the original author of this work. It is [Joe Walko](mailto://joewalko@gmail.com) - [cryptknock.sourceforge.net](http://cryptknock.sourceforge.net). This is just a port on github I've done for later use.

## License

I'ven't found any license in the code, so I hope That's ok to [Joe Walko](mailto://joewalko@gmail.com) if I've ported his code here. Will ask him later.

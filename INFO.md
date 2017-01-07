# Encrypted portknocking using Diffie Hellman & RC4

## 1. Introduction

This document is about using the `Diffie-Hellman` algorithm and the `SSL` library to build a secure `portknocking` system.

What's wrong with current portknockers? They can be easily sniffed and replayed:

	14:00:26.997642 12.150.172.185.55145 > 12.150.172.136.18: S 1954616956:1954616956(0) win 4096
	14:00:26.997703 12.150.172.185.55145 > 12.150.172.136.40324: S 1954616956:1954616956(0) win 3072
	14:00:26.997753 12.150.172.185.55145 > 12.150.172.136.500: S 1954616956:1954616956(0) win 2048
	14:00:26.997861 12.150.172.185.55145 > 12.150.172.136.8001: S 1954616956:1954616956(0) win 4096

The evesdropper now knows the `portknock` sequence is `8001, 40324, 18, 500`. The purpose of your `portknocker` is defeated and your network services are again exposed.

Granted, this is not much of an issue if the server you are knocking against is not on a LAN.
Not to mention portknocking could be considered security overkill to begin with. But for the extra paranoid, let's find a safer way to portknock by taking advantage of the `SSL` library, `libpcap`, and `UDP`.

## 2. Encrypted Communication Without Open Ports

Instead of using a series of `TCP` packets as our key, let's simply use a password.
We need to find a way to transmit this text string to the server, without requiring the server to actively listen on a socket. `UDP` and `libpcap` are our best friends here. `UDP` because no three-way handshakes are required to send data.

`Libpcap` because no open ports are required to receive data. Of course, our `portknock` password has to be encrypted, and the `OpenSSL` libraries have plenty of functions to help.

The implementation used in this program uses `RC4` to encrypt the password using a symmetric key created from the `Diffie-Hellman` handshake.

## 3. The Implementation

There are two programs: `cryptknock` and `cryptknockd`. They work as follows:

1. The user types `cryptknock -t <ip_address> -s <source_port> -d <dest_port>`, and the program prompts for the `cryptknockd` password. The client sends a `UDP` packet to the specified host and port. This packet contains the `p`, `g`, and `public key` values used for the `Diffie-Hellman` key agreement.

2. The server receives this packet, generates its private key based of the `p` value, and generates its public key based on `g` and the private key. The server then derives the shared secret (for use later). The server then sends its public key to the client.

3. The client receives the server's public key and derives the shared secret. Using the shared secret as the symmetric encryption key, the client encrypts the user's password (we use `RC4`), places it inside a `UDP` packet, and sends the packet to the server.

4. The server uses the shared secret to decrypt the password stored in the `UDP` packet. The server process compares this value to the `OPEN_PASSWORD` or `CLOSE_PASSWORD` strings.
If the password matches the `OPEN_PASSWORD`, the server adds an iptables allow rule for that `IP address`. If the password matches the `CLOSE_PASSWORD`, the server deletes the iptables allow rule corresponding to the client's address.

This entire process takes 3 udp packets:

	14:20:54.743273 IP 12.150.172.100.4500 > 12.150.172.185.9090: UDP, length: 517	(Client sends server request with DH parameters)
	14:20:54.783493 IP 12.150.172.185.32884 > 12.150.172.100.4500: UDP, length: 256	(Server responds with parameters)
	14:20:54.806656 IP 12.150.172.100.4500 > 12.150.172.185.9090: UDP, length: 200	(Client sends encrypted knock password to server)

> No ports ever need to be in a listening state for this to work.

This program was designed to be easy to use. An added benefit is that there is no need to remember all those port number combinations that other port knocking tools use. All you need is a password. On the network, instead of seeing the TCP ports used for a knock, all an evesdropping sees is encrypted traffic:

	14:08:35.872080 IP 12.150.172.100.4000 > 12.150.172.185.9090: UDP, length: 200

	0x0000   4500 00e4 0001 4000 4011 610e 3fdc ac88        E.....@.@.a.?...
	0x0010   3fdc acb9 0fa0 2382 00d0 7128 34b9 bc42        ?.....#...q(4..B
	0x0020   e1e1 2e43 faef 37bf 1466 86a5 bcd7 3281        ...C..7..f....2.
	0x0030   fe8e ffbd 450f 9d71 bab3 5c4a 853e 2af7        ....E..q..\J.>*.
	0x0040   8aad 2454 f978 d3a6 e1d1 ecd7 d119 575b        ..$T.x........W[
	0x0050   021d 0d18 2cff fa4b 59b3 2370 a8fd d22a        ....,..KY.#p...*
	0x0060   e48c 41ff 7a94 1660 e6e3 ac58 2c59 be69        ..A.z..`...X,Y.i
	0x0070   d825 2d11 73a4 5848 16d8 32d5 50be d7b6        .%-.s.XH..2.P...

> This is the password encrypted using RC with a DH key.

## 4. Iptables Interaction

Cryptknockd uses `iptables` to control firewalling/unfirewalling of hosts on an IP by IP address basis. When executed, `cryptknockd` forks and execs several `iptables` commands that do the following:

1. Flush all iptables rules to obtain a clean slate.
2. Adds a rule to allow new outbound connections.
3. Adds a rule to allow established connections.
4. Adds a rule to deny all incoming TCP traffic.

The program can be trivially changed to suit your firewalling needs. But the above rules should suffice for most of the population.

Upon receiving a valid open `knock password`, the `cryptknockd` server unfirewalls (via `ipchains`) all `TCP` ports for only that client IP. Upon receiving a valid close `knock password`, the server deletes the `iptables` allow rule for that address.

## 5. FAQs

Q. How do I compile these programs?

A. Like this:

```shell
gcc cryptknock.c -o cryptknock  -lssl -lcrypto
gcc cryptknockd.c -o cryptknockd -lssl -lcrypto -lpcap
```

Q. The program fails to compile using gcc with the error:

```shell
/tmp/ccjHSDRh.o(.text+0x82a): In function 'receive_ciphertext':
: undefined reference to 'pcap_breakloop'
/tmp/ccjHSDRh.o(.text+0xb23): In function 'dh_receive_packet':
: undefined reference to 'pcap_breakloop'
collect2: ld returned 1 exit status
```

...What's wrong?

A. Please upgrade your version of `libpcap` and see if that helps.

Q. I found a bug/made an improvement! What should I do?

A. Feel free to email [joewalko@gmail.com](mailto://joewalko@gmail.com) and let me know.

--joe

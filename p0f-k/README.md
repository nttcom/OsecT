# p0f-k

---

## What's this?

P0f-k is an enhanced version of p0f.
The original p0f is a tool that utilizes an array of sophisticated, purely passive traffic fingerprinting mechanisms to identify the players behind any incidental TCP/IP communications (often as little as a single normal SYN) without interfering in any way.

## Additional function

The functions added to p0f-k are as follows:

### 1. MAC address output

P0f-k outputs the MAC address like this:

```bash
.-[ 192.168.1.4(00:11:22:33:44:55)/1524 -> 10.0.0.1(00:11:22:66:77:88)/80 (syn) ]-
|
| client   = 192.168.1.4/1524
| os       = Mac OS X
| dist     = 0
| params   = generic fuzzy
| raw_sig  = 4:64+0:0:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:id-,ecn:0
|
`----

.-[ 192.168.1.4(00:11:22:33:44:55)/1524 -> 10.0.0.1(00:11:22:66:77:88)/80 (syn+ack) ]-
|
| server   = 10.0.0.1/80
| os       = Linux 2.4.x
| dist     = 0
| params   = none
| raw_sig  = 4:64+0:0:1460:mss*4,0:mss,nop,nop,sok,nop,ws:df:0
|
`----

.-[ 192.168.1.4(00:11:22:33:44:55)/1524 -> 10.0.0.1(00:11:22:66:77:88)/80 (syn) ]-
|
| client   = 192.168.1.4/1524
| os       = Mac OS X
| dist     = 0
| params   = generic fuzzy
| raw_sig  = 4:64+0:0:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:id-,ecn:0
|
`----

.-[ 192.168.1.4(00:11:22:33:44:55)/1524 -> 10.0.0.1(00:11:22:66:77:88)/80 (syn+ack) ]-
|
| server   = 10.0.0.1/80
| os       = Linux 2.4.x
| dist     = 0
| params   = none
| raw_sig  = 4:64+0:0:1460:mss*4,0:mss,nop,nop,sok,nop,ws:df:0
|
`----
```

### 2. New format log output

P0f-k can output logs in tabbed format. This function logs the OS estimation by TCP SYN and SYN + ACK when the -O option is specified. The log output looks like this:

```bash
1578584182.881877     syn         192.168.1.4     00:11:22:33:44:55     Mac OS X        4:64+0:0:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:id-,ecn:0
1578584186.691955     syn+ack     10.0.0.1        00:11:22:66:77:88     Linux 2.4.x     4:64+0:0:1460:mss*4,0:mss,nop,nop,sok,nop,ws:df:0
1578584187.980917     syn         192.168.1.4     00:11:22:33:44:55     Mac OS X        4:64+0:0:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:id-,ecn:0
1578584214.298396     syn+ack     10.0.0.1        00:11:22:66:77:88     Linux 2.4.x     4:64+0:0:1460:mss*4,0:mss,nop,nop,sok,nop,ws:df:0
```

### 3. Fingerprint database update

P0f-k supports fingerprinting for new operating systems like Windows 10.

## Usage

The usage of p0f-k is the same as the original p0f.

Here's how to use the added -O option. The -O and -o options cannot be executed at the same time.

```bash
$ sudo ./p0f -i ens33 -d -O /var/log/p0f-k.log
(Omitted)

$ ./p0f -r some_capture.pcap -O /tmp/p0f-k.log
(Omitted)
```

## License

Copyright 2021 NTT Communications Corporation.

Distributed under the terms and conditions of GNU LGPL.

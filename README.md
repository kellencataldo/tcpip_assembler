# Windows TCP/IPv4 Conversation assembler and packet analyzer

## Overview

This is a tool which will reconstruct TCP/IPv4 conversations between all IP's or a specific IP and across all ports or a specific port from data collected in a PCAP file. The tool will sort individual TCP conversations by packets and SEQ number and organize them between upload data and download data. Along with sorting the connections and packets, anomalous events detected in the TCP conversations such as an incorrect TCP teardown, set RESET bits, and duplicate packets being sent will be highlighted in the output file. This tool can be used to analyze network behavior coming into a Windows system in order to track suspicious behavior.

## How to use

I have uploaded the source code for this project as well as the .sln file. If you have Visual Studio the source code can be downloaded and opened in Visual Studio. If not, simply download the .h and .cpp files separately and compile them. **Note:** This program was designed for Windows machines and therefore makes it extremely unportable. It will not compile on a Linux machine using GNU unfortunately. I have also attached the exe which can be downloaded separately.

This tool operates on PCAP files. PCAP files are generated by certain programs which moniter all network traffic coming in and out of a system and generate a file of packets and raw data. Some popular PCAP file generating programs for Windows are WinPcap and Wireshark. Simple run on of these programs and network traffic will be monitered until the program is terminated. 

This tool is a command line application and can take several arguments in order to change the desired output value. By default, the output is a file containing a global header providing an overview of all packets examined,conversation headers which display information about a specific conversation between two IP's on two ports, and individual packet headers. More information about these headers and the information they generate will be included in the **What to look for** section. 

All of these can be turned off individually along with setting several other options. In total there are xx commands:

>Toggle global header: **-gh**

>Toggle conversation headers: **-ch**

>Toggle packet headers: **-ph**

>Filter by a specific port: **-port #**

>Filter by a specifi IP (human readable format): **-ip #**

>Do not display data: **-nd**

By default, the maximum size of the data is 10 MB, this can be manually increased by megabyte number to a maximum of 2 GB. The command for this is

>Resize maximum data: **-rs #**

All of these commands can be given in any order. For example to examine packets from a specific IP on a specific port without displaying connection headers and packet headers and resizing the maximum data amount to 15 megabytes, this command would be used:

```
ip_convo.exe -ip 127.0.0.1 -port 80 -ch -ph -rs 15
```

In order to input a file, the stream must be directed to the stdin of the exe using **<**. This is done after adding any inputs. For example, if the path to the PCAP file was C:\path\to\example.pcap then the previous command would become:

```
ip_convo.exe -ip 127.0.0.1 -port 80 -ch -ph -rs 15 < C:\path\to\example.pcap
```

This will print the output values to the Windows cmd prompt. You probably don't want that. You really, really don't want that. In order to redirect the output stream use **>** and point to the path of the desired output file (there does not have to be a file in this location previous to running the command). For example, if the desired output path was C:\path\to\output.txt the previous command now becomes: 

```
ip_convo.exe -ip 127.0.0.1 -port 80 -ch -ph -rs 15 < C:\path\to\example.pcap > C:\path\to\output.txt
```

## What to look for

This is an example output generated from network activity

![example](http://i.imgur.com/TucqqZ6.png)


## How it works



If you need to examine UDP, or another protocal such as ARP, this is best left to a more robust
tool such as Wireshark.

The problem is you are not linking against the Ws2_32.lib library

Denial of service attack on a POP3 server caused by issuing the same command thousands of times. 
One signature for this attack would be to keep track of how many times the 
command is issued and to alert when that number exceeds a certain threshold. #port 110 but other ports for email too
Another type of attack that this tool will reveal is the a syn-flood attack. TCP will leave a connection open if the
connection did not successfully signify that it was closing. attackers can take advantage of this by repeatedly
opening up connections on ports without closing the connection. this causes ports to listen for a connection that isnt there
and therefore reject other valid connections as the avaliable ports shrink. this is essentially a 
sophisticated form of a DDoS attack.
Another type of attack that this tool will reveal is an ack flooding attack. when this occurs, a malicious connection
will repeatedly send the incorrect ack number to the host and therefore because of hte way tcp is implemented, the 
host will faithfully attempt to respond with the correct sequence of data until the connection is terminated.
this is similar to the syn_flooding attack except that the port is essentially held hostange as the connection will not time out.

include upload data, download data
include only the header
examine only a specific port


if (option set && correct port) or (option not set)

IPV6 support has not been added as it would take considerably more effort 
(ipv6 are often encapsulated under ipv4 so as to path through ipv4 only networks. this process is called
a 6to4 transmission). 
if you wanted to try examining ipv6 packets yourelf, i would suggest using type templates etc.
An ipv6 packet that has been ecanpsulated in an ipv4 packet will have a protocol type of 41. With that,
it should be a relatively easy process using structure templates to sort between ipv4 packets, and ipv4 packets
with an ipv6 packet encapsulated underneath.

the conversations are sorted and ordered using a pairing function 
the pairing function is generated in an anonymous function using the cantor sum, a quadratic pairing function
this makes it a relativley simple task to check if a conversation between two IP's has already been stored
unlike georg contors function, i am using a Z-order curve to pair my values as working with bits in c++ is far easier
than working with big numbers. this means that given two numbers of size n, the unique result is guarenteed to be less than 2n

ntohs is an inline function which makes it less computationally heavy on the compiler (??)

structures can often be treated as classes in c++ and have their own functions

im using the bubble sort algorithm because it works very well on nearly sorted data sets. this should be the case for most packets as
tcp will reject multiple out of place packets (?). i chose not to rely on the supplied vector::sort algorithm as i
don't know the time complexity of the function.

the TCP sequence number are a random large unsigned value. this is essentially a type of encryption and makes it very difficult
for malicious connections to fake their identity.

there is one fatal flaw which sort of puts a dent in the use of this tool which I will get into later (next line)

i wanted to add support for switching the type of encoding from binary to utf 8 to utf 16 to text etc. however,
it appears that windows has a bug related to writing utf8 and utf16 test to the command line which causes
exe's to crash. unfortunant.

tcp reset attack

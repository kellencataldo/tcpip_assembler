# tcpip_assembler

##overview

This is a tool which will reconstruct TCP/IP conversations across all ports or a given port.r
If you need to examine UDP, or another protocal such as ARP, this is best left to a more robust
tool such as Wireshark.

You can redirect the output stream into a file like this > output.txt

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

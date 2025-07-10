# ping_of_death

Ping of Death is a type of Denial-of-Service (DoS) attack where an attacker sends malicious or oversized ICMP Echo Request (ping) packets to a target system.


Normally, ping packets are limited to 65,535 bytes, but the Ping of Death attack manipulates packet fragments to exceed this limit once reassembled. 
This can cause buffer overflows, system crashes, reboots, or freezes in vulnerable systems. 
While modern operating systems have been patched against such attacks, legacy systems and misconfigured networks may still be at risk. 
The Ping of Death exploits weaknesses in how systems process fragmented network packets, disrupting services and network stability.

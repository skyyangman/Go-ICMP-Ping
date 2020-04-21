## What is it?

- Its a small Ping CLI application for MacOS or Linux. Support for both IPv4 and IPv6, and allow to set TTL as an argument and report the corresponding "time exceeded” ICMP messages.
- The CLI app accept a hostname or an IP address as its argument, then send ICMP "echo requests" in a loop to the target while receiving "echo reply" messages. 
It report loss and RTT times for each sent message.

## Usage
- -c to set number of times to send ping request.
- -i to set time (in second) between ping request.
- -t to set the TTL.
- -s to set the packet size.

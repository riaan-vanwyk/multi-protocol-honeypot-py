# EchoTrap: A Python FTP, SSH & Telnet Honeypot
#### Description: 
##### 1. Introduction
EchoTrap is, as the name suggests, a small Python system designed to attract malicious activity in the hopes that they will connect to a honeypot, rather than a real Enterprise system, so that you can take action and mitigate real damage before it even happens. Of course, this is just a basic honeypot, but the "designed to attract malicious activity" part has still been added. This honeypot opens FTP, SSH, and Telnet ports on any local network / the internet, sending fake and rotating connection and login banners to emulate a real FTP, SSH, and Telnet server. The main goal of this project was for me to understand network interfaces, different network protocols, concurrency better, as well to learn more about Cloud Detection Engineering. The project also does SIEM-like logging via /logs/honeypot_logs.json, although I haven't tested/integrated it into a real SIEM yet. 

##### 2. Features

I tried to add as many features as reasonably possible within the `logging`, `sockets`, `threading` landscape. First of all, most importantly, I added a way to listen and connect, and safely disconnect from any IP address that wants to connect to the computer running the script via port 21, 22, 23, also 8021, 8022, 8023 (If you're running some sort of VPS / firewall that cannot support low ports. Then I send fake text, especially for the Telnet to make it look like a real Telnet loging prompt; not just to convince another Grabber / Scanner, but also probably someone using PuTTY to make it look believable enough. Then I started adding the "rotating banner" feature. Every time an attacker connects, it gets assigned a pseudo-random (IP as seed) "banner" to send, since mostly the program will not interface with real humans but rather Scanners / Grabbers which actually read the information banner first before sending any data. The consequence of making the banner's seed the attacker's IP, is that the same IP will get the same banner, which makes it more believable. I also added a basic "threat scoring" system, just a few `if` statements, but enough to get the concept across of a basic threat evaluation system, because it is better for humans to see at a glance what is happening with their security posture, rather than to dig through thousands of logs every day. I have also added a "port scan detection" system to the project, basically a detection if 2 or more unique ports have been hit in 5 seconds or less, and prints the parameters to the screen. Of course, this is changeable. Every connection also has a unique ID, thanks to a UUID4 string generation inside of the program. This is helpful for logging, if you want to track down a specific connection after it has happened or if you are making a database of logs. My program also has 3 threads, as most of the logs would be lost if I constantly cycled between ports, as Grabbers / Bots act very fast. This means that each protocol can accept and process incoming TCP sessions independently. The main thread remains alive while the listener threads handle incoming traffic in parallel. My program also has a JSON output function where it writes all of the things such as timestamp, protocol. attacker IP address, the atacker's port, the target port on the victim machine/network, which banner the program sent to the attacker after he has connected, connection metadata such as the connection UUID, if the connection timed out and thus I forcefully disconnected the attacked to prevent it hogging up the thread, or it self-disconnected, how long it was connected, what data the attacker sent to the victim device over the network, and all of the basic threat evaluation system's parameters. 

##### 3. Architecture
##### Threading System
Here is a basic diagram of how the threading system works: 

![How the threading system works](https://riaanvanwyk.onrender.com/A.png)<br>
These threads listen simultaneously for incoming connections, handle interactions without blocking each other, and send all data back to a shared logging and threat scoring module. When the application closes, all socket threads properly and safely close as they are daemon threads. 

##### Socket handling system
Here is a basic diagram of how the socket handling system works: 
![How the threading system works](https://riaanvanwyk.onrender.com/B.png)<br>
Using the Python `sockets` module, I start by making and initialising a new socket object for EACH of the three ports, as each thread calls a function that initialises a new socket object. Each socket object then listens for an incoming connection on its respective port and then connects. Then it handles the connection differently depending on which protocol (port) has been connected to. Then we properly close the connection after 5 seconds of timeout if the attacker does not disconnect (to prevent one rogue port-blocking attacker from hogging the port for hours/days/never disconnecting), or, if the attacker disconnects, I properly close the connection to the attacker using the `conn.close()` function. The daemon threads ensure that each listener socket is properly destroyed when the program terminates, allowing the operating system to automatically release the associated ports.

##### Storing of logs 
Here is a basic diagram of how the storing of logs works: <br>
![How the threading system works](https://riaanvanwyk.onrender.com/E.png)<br>
Each thread constructs a structured log object (LOG_DICT) containing the full session — including banners, payloads, metadata, and threat scoring. The log is then written thread‑safely to honeypot_logs.json using a global file_lock to prevent race conditions.

##### 3. Installation / Requirements 

##### 4. Usage Instructions 

##### 5. Directory Structure 

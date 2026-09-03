# EchoTrap: A Python FTP, SSH & Telnet Honeypot
Video Demo: [🎥 View Video Demo](https://riaanvw.vercel.app/EchoTrap_PresentationVideo.html)

Presentation: [📄 View Full Presentation](https://riaanvw.vercel.app/EchoTrap_Presentation.html)
<br><br>
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)

#### Description:

##### 1. Introduction
EchoTrap is, as the name suggests, a small Python system designed to attract malicious activity in the hopes that they will connect to a honeypot, rather than a real Enterprise system, so that you can take action and mitigate real damage before it even happens. Of course, this is just a basic honeypot, but the "designed to attract malicious activity" part has still been added. This honeypot opens FTP, SSH, and Telnet ports on any local network / the internet, sending fake and rotating connection and login banners to emulate a real FTP, SSH, and Telnet server. The main goal of this project was for me to understand network interfaces, different network protocols, concurrency better, as well to learn more about Cloud Detection Engineering. The project also does SIEM-like logging via /logs/honeypot_logs.json, although I haven't tested/integrated it into a real SIEM yet. 

##### 2. Features

I tried to add as many features as reasonably possible within the `logging`, `sockets`, `threading` landscape. First of all, most importantly, I added a way to listen and connect, and safely disconnect from any IP address that wants to connect to the computer running the script via port 21, 22, 23, also 8021, 8022, 8023 (If you're running some sort of VPS / firewall that cannot support low ports. Then I send fake text, especially for the Telnet to make it look like a real Telnet loging prompt; not just to convince another Grabber / Scanner, but also probably someone using PuTTY to make it look believable enough. Then I started adding the "rotating banner" feature. Every time an attacker connects, it gets assigned a pseudo-random (IP as seed) "banner" to send, since mostly the program will not interface with real humans but rather Scanners / Grabbers which actually read the information banner first before sending any data. The consequence of making the banner's seed the attacker's IP, is that the same IP will get the same banner, which makes it more believable. I also added a basic "threat scoring" system, just a few `if` statements, but enough to get the concept across of a basic threat evaluation system, because it is better for humans to see at a glance what is happening with their security posture, rather than to dig through thousands of logs every day. I have also added a "port scan detection" system to the project, basically a detection if 2 or more unique ports have been hit in 5 seconds or less, and prints the parameters to the screen. Of course, this is changeable. Every connection also has a unique ID, thanks to a UUID4 string generation inside of the program. This is helpful for logging, if you want to track down a specific connection after it has happened or if you are making a database of logs. My program also has 3 threads, as most of the logs would be lost if I constantly cycled between ports, as Grabbers / Bots act very fast. This means that each protocol can accept and process incoming TCP sessions independently. The main thread remains alive while the listener threads handle incoming traffic in parallel. My program also has a JSON output function where it writes all of the things such as timestamp, protocol. attacker IP address, the atacker's port, the target port on the victim machine/network, which banner the program sent to the attacker after he has connected, connection metadata such as the connection UUID, if the connection timed out and thus I forcefully disconnected the attacked to prevent it hogging up the thread, or it self-disconnected, how long it was connected, what data the attacker sent to the victim device over the network, and all of the basic threat evaluation system's parameters. 

##### 3. Architecture
##### Threading System
Here is a basic diagram of how the threading system works: 

<img src="https://riaanvanwyk.onrender.com/A.png" alt="Threading System Diagram"><br>
These threads listen simultaneously for incoming connections, handle interactions without blocking each other, and send all data back to a shared logging and threat scoring module. When the application closes, all socket threads properly and safely close as they are daemon threads. 

##### Socket handling system
Here is a basic diagram of how the socket handling system works: 
<img src="https://riaanvanwyk.onrender.com/B.png" alt="Socket Handling System Diagram"><br>
Using the Python `sockets` module, I start by making and initialising a new socket object for EACH of the three ports, as each thread calls a function that initialises a new socket object. Each socket object then listens for an incoming connection on its respective port and then connects. Then it handles the connection differently depending on which protocol (port) has been connected to. Then we properly close the connection after 5 seconds of timeout if the attacker does not disconnect (to prevent one rogue port-blocking attacker from hogging the port for hours/days/never disconnecting), or, if the attacker disconnects, I properly close the connection to the attacker using the `conn.close()` function. The daemon threads ensure that each listener socket is properly destroyed when the program terminates, allowing the operating system to automatically release the associated ports.

##### Storing of logs 
Here is a basic diagram of how the storing of logs works: <br>
<img src="https://riaanvanwyk.onrender.com/E.png" alt="Log Storing System Diagram"><br>
Each thread constructs a structured log object (LOG_DICT) containing the full session — including banners, payloads, metadata, and threat scoring. The log is then written thread‑safely to honeypot_logs.json using a global file_lock to prevent race conditions.

##### Threat Scoring 
Here is a basic diagram of how the threat scoring system works: <br>
<img src="https://riaanvanwyk.onrender.com/F.png" alt="Threat Scoring System Diagram"><br>
EchoTrap assesses all connections by means of a straightforward but efficient threat-scoring technique. This system takes into account the number of attacks and the duration of the connection. Depending on these variables, the honeypot classifies the type of intrusion as a port scan, idle probing, etc. After classification, the information gets associated with a numerical index which maps a confidence level (medium, low, high).
##### 3. Installation,  Requirements and Execution
You'll need Python3, and  if on Windows 7+, you can just double-click the start.bat file. If not on Windows, manually launch `python3 project.py` from the Terminal. To run the Python sanity tests, just execute `python pytest.py` in the terminal; it will automatically detect the prescence of `test_*.py` (in this case, `test_project.py`). There are no external dependancies that need to be installed, just make sure that all of the built-in python modules (socket, sys, threading, time, json, datetime, uuid, random, os, collections) are actually working, which they should be if you installed Python normally. 

##### 4. Usage Instructions 
When honeypot.py is launched, all three listener threads (FTP, SSH, and Telnet) start automatically.
Each thread opens its respective port pair:

FTP: 21 and 8021

SSH: 22 and 8022

Telnet: 23 and 8023

These ports begin listening immediately for incoming TCP connections.

You can stop the honeypot at any time using:

Ctrl + C in the terminal

Closing the terminal window
##### 5. Example Log output 

Here is an example of one of the lines that you may find in honeypot_logs.json (broken up into multiple lines for readablity):

```json
{
   "timestamp":"2026-07-20T17:55:23.774Z",
   "protocol":"ftp",
   "attacker_ip":"45.155.205.12",
   "attacker_port":33912,
   "target_port":21,
   "banner_sent":"220 FileZilla Server 0.9.60 beta",
   "connection_metadata":{"connection_id":"a7b8c9d1-2e33-4f44-9a55-5b6c7d8e9f00",
   "timed_out":true,
   "disconnect_reason":"forcibly_closed_after_timeout",
   "connection_duration_ms":5000},
   "payloads_received":[],
   "threat":
   {
      "category":"port_scan",
      "score":2,
      "confidence":"low"
   }
}
```

##### 6. Directory Structure
```text
Project Structure -> 

(Folder) FinalProject 
   ---> project.py - This is where the FTP , SSH, Telnet handling, Fake banner sending, response logging, and the entire Honeypot is located 
   ---> test_project.py - This file implements unit testing for the file "project.py" to ensure that the project is working correctly.
   ---> requirements.txt - what python packages you need installed 
   ---> README.md - Description of everything
   ---> start.bat - It opens `python project.py` , and keeps the console open afterwards so that you can read any errors that might occur
   ---> Struct.txt - A copy of this same Project Structure definition (this file) 
   ---> pytest.py - This is for testing the program.
   (Folder) logs ->
         - honeypot_logs.json -> Contains all of the SIEM-compatible json logs and simple treat evaluation that the honeypot gathers for however long it is active

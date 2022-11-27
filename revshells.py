import os, platform
from packet import languages

if(platform.system() == "Windows"):
    os.system("cls")
else:
    os.system("clear")

def ascii_art():
    print('''
                            ,--.                    OS(                      Language(
                           {    }                       windows,                   bash         (linux, mac)
                           K,   }                       linux,                     nc           (linux, windows)
                          /  ~Y`                        mac,                       c            (linux, windows, mac)
                     ,   /   /                          all                        c#           (linux, windows)
                    {_'-K.__/                       )                              haskell      (linux, mac)
                      `/-.__L._                                                    perl         (linux, mac)
                      /  ' /`\_}                    Shells(                        php          (linux, windows, mac)
                     /  ' /                             sh,                        conPty       (linux)
             ____   /  ' /                              /bin/sh,                   powershell   (linux)
      ,-'~~~~    ~~/  ' /_                              bash,                      python       (linux, windows, amc)
    ,'             ``~~~  ',                            /bin/bash,                 ruby         (linux, mac)
   (                        Y                           cmd,                       socat        (linux, mac)
  {                         I                           powershell,                nodejs       (linux, windows, mac)
 {      -                    `,                         pwsh,                      java         (linux, windows, mac)
 |       ',                   )                         ash,                       javascript   (linux, windows, mac)
 |        |   ,..__      __. Y                          bsh,                       groovy       (linux, windows)
 |    .,_./  Y ' / ^Y   J   )|                          csh,                       telnet       (linux, mac)
 \           |' /   |   |   ||                          ksh,                       zsh          (linux, mac)
  \          L_/    . _ (_,.'(                          zsh,                       lua          (linux, windows)
   \,   ,      ^^""' / |      )                         pdksh,                     golang       (linux, windows, mac)
     \_  \          /,L]     /                          tcsh                       vlang        (linux, mac)
       '-_~-,       ` `   ./`                       )                              awk          (linux)
          `'{_            )                                                        dart         (linux, windows)
              ^^\..___,.--`                                                        powershell   (windows)
              ''')

ascii_art()

system = input("\n\n\n Enter the OS: ")

ip = input("\n Enter the attacker ip => ")

port = int(input("\n Enter the attacker port => "))

shells = input("\n Enter the shell => ")

if(system != "all"):
    language = input("\n Enter the language => ")

if(system == "linux"):
    languages.main(ip, port, shells)
    if(language == "bash"):
        languages.bash(ip, port, shells)
    elif(language == "nc"):
        languages.nc(ip, port, shells)
    elif(language == "c"):
        languages.C(ip, port, shells)
    elif(language == "c#"):
        languages.CSharp(ip, port, shells)
    elif(language == "hackell"):
        languages.haskell(ip, port, shells)
    elif(language == "perl"):
        languages.perl(ip, port, shells)
    elif(language == "php"):
        languages.PHP(ip, port, shells)
    elif(language == "python"):
        languages.python_shell(ip, port, shells)
    elif(language == "ruby"):
        languages.ruby(ip, port, shells)
    elif(language == "socat"):
        languages.socat(ip, port, shells)
    elif(language == "nodejs"):
        languages.nodeJS(ip, port, shells)
    elif(language == "java"):
        languages.java(ip, port, shells)
    elif(language == "javascript"):
        languages.Javascript(ip, port, shells)
    elif(language == "groovy"):
        languages.Groovy(ip, port, shells)
    elif(language == "telnet"):
        languages.telnet(ip, port, shells)
    elif(language == "zsh"):
        languages.zsh(ip, port, shells)
    elif(language == "lua"):
        languages.lua(ip, port, shells)
    elif(language == "golang"):
        languages.Golang(ip, port, shells)
    elif(language == "vlang"):
        languages.Vlang(ip, port, shells)
    elif(language == "awk"):
        languages.Awk(ip, port, shells)
    elif(language == "dart"):
        languages.Dart(ip, port, shells)
elif(system == "windows"):
    languages.main(ip, port, shells)
    if(language == "nc"):
        languages.nc(ip, port, shells)
    elif(language == "c"):
        languages.C(ip, port, shells)
    elif(language == "c#"):
        languages.CSharp(ip, port, shells)
    elif(language == "php"):
        languages.PHP(ip, port, shells)
    elif(language == "powershell"):
        languages.powershell(ip, port, shells)
    elif(language == "python"):
        languages.python_windows_shell(ip, port, shells)
    elif(language == "nodejs"):
        languages.nodeJS2(ip, port, shells)
    elif(language == "java"):
        languages.java3(ip, port, shells)
    elif(language == "javascript"):
        languages.Javascript(ip, port, shells)
    elif(language == "groovy"):
        languages.Groovy(ip, port, shells)
    elif(language == "lua"):
        languages.lua2(ip, port, shells)
    elif(language == "golang"):
        languages.Golang(ip, port, shells)
    elif(language == "dart"):
        languages.Dart(ip, port, shells)
    else:
        print("\n Error. language not found")
elif(system == "mac"):
    languages.main(ip, port, shells)
    if(language == "bash"):
        languages.bash(ip, port, shells)
    elif(language == "nc"):
        languages.nc(ip, port, shells)
    elif(language == "c"):
        languages.C(ip, port, shells)
    elif(language == "haskell"):
        languages.haskell(ip, port, shells)
    elif(language == "perl"):
        languages.perl(ip, port, shells)
    elif(language == "php"):
        languages.PHP(ip, port, shells)
    elif(language == "python"):
        languages.python_shell(ip, port, shells)
    elif(language == "ruby"):
        languages.ruby(ip, port, shells)
    elif(language == "socat"):
        languages.socat(ip, port, shells)
    elif(language == "nodejs"):
        languages.nodeJS(ip, port, shells)
    elif(language == "java"):
        languages.java(ip, port, shells)
    elif(language == "javascript"):
        languages.Javascript(ip, port, shells)
    elif(language == "telnet"):
        languages.telnet(ip, port, shells)
    elif(language == "zsh"):
        languages.zsh(ip, port, shells)
    elif(language == "golang"):
        languages.Golang(ip, port, shells)
    elif(language == "vlang"):
        languages.Vlang(ip, port, shells)
    elif(language == "awk"):
        languages.Awk(ip, port, shells)
    elif(language == "dart"):
        languages.Dart(ip, port, shells)
    else:
        print("\n Error. language not found")
elif(system == "all"):
    languages.main
    languages.alls(ip, port, shells)
else:
    print("\n Error, os not found")
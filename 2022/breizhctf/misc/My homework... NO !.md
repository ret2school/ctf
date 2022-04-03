# [BreizhCTF2020 - Misc] My homework... NO !

    Description:
    Je dois rendre mon tp ce soir mais j'ai supprimé le dossier où se trouvaient mes bianires. Par chance il tourne encore, pouvez-vous m'aider à le récupérer ?

    Login/Password : gaston:gaston

    ssh challenges.ctf.bzh:24001

    Auteur: LaChenilleBarbue

    Format : BZHCTF{sha512sum(binaire)}

Let's start by connecting to the server with the credentials we have been given and list the processes that are running:
```
> ssh challenges.ctf.bzh -p 24001 -l gaston
gaston@challenges.ctf.bzh's password:
gaston@726bc5597730:~$ ps -aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   2616   536 ?        Ss   20:32   0:00 /bin/sh /entrypoint.sh
gaston        13 99.8  0.0   2364   512 ?        R    20:32  59:22 /home/gaston/hellobreizh.bin
root          15  0.0  0.0  12180  7372 ?        S    20:32   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root         304  0.0  0.0  13148  8620 ?        Ss   20:38   0:00 sshd: gaston [priv]
gaston       315  0.0  0.0  13388  5988 ?        S    20:38   0:00 sshd: gaston@pts/3
gaston       316  0.0  0.0   4248  3472 pts/3    Ss   20:38   0:00 -bash
gaston       398  0.0  0.0   6104  3200 pts/3    S+   20:40   0:01 top
root        1940  0.0  0.0  13148  8156 ?        Ss   21:20   0:00 sshd: gaston [priv]
gaston      1952  0.1  0.0  13736  6408 ?        S    21:20   0:00 sshd: gaston@pts/1
gaston      1965  0.0  0.0   4248  3528 pts/1    Ss+  21:20   0:00 -bash
gaston      1968  0.1  0.0   3904  2772 ?        Ss   21:20   0:01 bash -c while [ -d /proc/$PPID ]; do sleep 1;head -v -n 8 /proc/meminfo; head -v -n 2 /proc/stat /proc/version /proc/uptime /proc/loadavg /pro
root        5469  0.0  0.0  13388  8728 ?        Ss   21:30   0:00 sshd: gaston [priv]
gaston      5492  0.0  0.0  13388  4596 ?        S    21:30   0:00 sshd: gaston@pts/0
gaston      5493  0.0  0.0   6000  3824 pts/0    Ss+  21:30   0:00 -bash
root        5681  0.0  0.0  13388  8632 ?        Ss   21:30   0:00 sshd: gaston [priv]
gaston      5698  0.0  0.0  13388  4864 ?        S    21:30   0:00 sshd: gaston@pts/4
gaston      5699  0.0  0.0   4248  3424 pts/4    Ss+  21:30   0:00 -bash
root        5848  0.1  0.0  13148  8296 ?        Ss   21:31   0:00 sshd: gaston [priv]
gaston      5871  0.0  0.0  13388  4984 ?        S    21:31   0:00 sshd: gaston@pts/2
gaston      5872  0.0  0.0   6000  3828 pts/2    Ss+  21:31   0:00 -bash
root        5942  0.3  0.0  13148  8428 ?        Ss   21:31   0:00 sshd: gaston [priv]
gaston      5966  0.0  0.0  13388  5116 ?        R    21:31   0:00 sshd: gaston@pts/5
gaston      5967  0.0  0.0   6000  3900 pts/5    Ss   21:31   0:00 -bash
gaston      5995  0.0  0.0   2516   516 ?        S    21:31   0:00 sleep 1
gaston      5996  0.0  0.0   7892  3308 pts/5    R+   21:31   0:00 ps -aux
```
Now that we have found the process we are interested in, we can dump it and make a sha512 of the obtained binary:
```
gaston@726bc5597730:~$ cat /proc/13/exe > mh
gaston@726bc5597730:~$ sha512sum ./mh
932abb57c2d1ccad065288579662af5216ed8a8aa4b8aa714d13feb6cb89570eed18bef0bcb7fda33e1b3bee9534c231a5ce349c01399687fe9495cf047db5ae  ./mh
```

```
BZHCTF{932abb57c2d1ccad065288579662af5216ed8a8aa4b8aa714d13feb6cb89570eed18bef0bcb7fda33e1b3bee9534c231a5ce349c01399687fe9495cf047db5ae}
```
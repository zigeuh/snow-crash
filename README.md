# snow-crash

## level00

<details>

<summary> Explanations</summary>

### Finding hints

For the **level00**, nothing relevant is provided in the /home/user/level00 directory. Since we are trying to log on the flag00 user, we can take a look at every files this user owns. To do so, we can use the ``find`` command. In our case:
```bash
find / -user flag00 2> /dev/null
```
The error redirection ``2> /dev/null`` is used to suppress all errors that are irrelevant in our case.

With this command, we get 2 results:
```bash
/usr/sbin/john
/rofs/usr/sbin/john
```

These are classic files, so we can inspect their content with the ``cat`` command. Both of them output the same result:
```bash
cdiiddwpgswtgt
```

At first glance, this could look like a password, so let's try it:
```bash
level00@SnowCrash:~$ su flag00
Password: 
su: Authentication failure
```

This means that this is not the password we are looking for. However, this still could be an **encrypted password**.

### Cipher Identification

To verify our theory, we are going to use the french website [dcode](https://www.dcode.fr/) since this website gives us a very effective [Cipher Identifier](https://www.dcode.fr/cipher-identifier)

After submitting the string ``cdiiddwpgswtgt``, several possible ciphers are shown. Among all of possible relevant ciphers, only some of them actually decode to the same result:
- Affine Cipher
- Disk Cipher
- ROT Cipher
- Caesar Cipher

We might not know all ciphers, but the **Caesar Cipher** is a well-known one. It consists in shifting letters a certain amount of time in a direction:
|  Original  |  a  |  b  |  c  |  d  |  e  |  f  |  g  |  h  |  i  |  j  |  k  |  l  |  m  |  n  |  o  |  p  |  q  |  r  |  s  |  t  |  u  |  v  |  w  |  x  |  y  |  z  |
| :--------: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
|    1 🠜    |  b  |  c  |  d  |  e  |  f  |  g  |  h  |  i  |  j  |  k  |  l  |  m  |  n  |  o  |  p  |  q  |  r  |  s  |  t  |  u  |  v  |  w  |  x  |  y  |  z  |  a  |
|    2 🠞    |  y  |  z  |  a  |  b  |  c  |  d  |  e  |  f  |  g  |  h  |  i  |  j  |  k  |  l  |  m  |  n  |  o  |  p  |  q  |  r  |  s  |  t  |  u  |  v  |  w  |  x  |
|    15 🠞   |  l  |  m  |  n  |  o  |  p  |  q  |  r  |  s  |  t  |  u  |  v  |  w  |  x  |  y  |  z  |  a  |  b  |  c  |  d  |  e  |  f  |  g  |  h  |  i  |  j  |  k  |

In our case, ``cdiiddwpgswtgt`` is a right shift of 15.

### Authentication

So now that we have the decoded string ``nottoohardhere``, we can try to log on the flag00 user:
```bash
level00@SnowCrash:~$ su flag00
Password: 
Don't forget to launch getflag !
flag00@SnowCrash:~$
```

### Retrieving the flag

It worked! We are in. So now, as they ask us to do, we are going to launch getflag:
```bash
flag00@SnowCrash:~$ getflag
Check flag.Here is your token : x24ti5gi3x0ol2eh4esiuxias
```

We got our flag! Let's see if this is the right flag to go onto the next level:
```bash
flag00@SnowCrash:~$ su level01
Password: 
level01@SnowCrash:~$ 
```

It was indeed the right flag.

</details>

## level01

<details>

<summary>Explanations</summary>

###

For this **level01**, we can, in first place try, to find eventually files owned by flag01, like we did previously:
```bash
level01@SnowCrash:~$ find / -user flag01 2> /dev/null
level01@SnowCrash:~$ 
```

Nothing was found. We are starting from scratch.

### Finding hints

There is something we could have done in level00 that we didn't do, and this is checking database of users.
On linux there is a file named ``passwd`` that contains user login accounts. This file is located in the ``/etc`` directory. So let's ``cat`` this file and ``grep`` everything about our flag01 user:
```bash
level01@SnowCrash:~$ cat /etc/passwd | grep flag01
flag01:42hDRfypTqqnw:3001:3001::/home/flag/flag01:/bin/bash
```

After launching the command, we come across a weird string linked to flag01: ``42hDRfypTqqnw``

If we take a look at others lines of ``/ect/passwd``, we can see there is not anything similar to this:
```
flag02:x:3002:3002::/home/flag/flag02:/bin/bash
flag03:x:3003:3003::/home/flag/flag03:/bin/bash
flag04:x:3004:3004::/home/flag/flag04:/bin/bash
flag05:x:3005:3005::/home/flag/flag05:/bin/bash
flag06:x:3006:3006::/home/flag/flag06:/bin/bash
```

We can try to use this as a password to log on flag01:
```bash
level01@SnowCrash:~$ su flag01
Password: 
su: Authentication failure
```

This is not it, but let's think for a second. Where do we save not encrypted passwords ?

Nowhere.

We **always** hash passwords. Which means, this is probably a hashed password too!

Good to know, but how are we supposed to crack a hashed password ?

### Cracking the password

**John the Ripper**.

John the Ripper is a wonderful tool when it's about cracking passwords. It autodetects the used algorithm and do its job in consequences.

So let's try using ``john`` on a file containing the password (our ``john`` package is built outside of the VM in a Dockerfile with an entrypoint ``john``):
```bash
➜  level01 git:(main) ✗ docker run john:latest password
Created directory: /root/.john
Loaded 1 password hash (descrypt, traditional crypt(3) [DES 128/128 SSE2])
Will run 20 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
abcdefg          (?)
1g 0:00:00:00 100% 2/3 50.00g/s 4096Kp/s 4096Kc/s 4096KC/s 123456..Melvin!
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

### Authentication

After ``john`` did its work, we can observe something very interesting: ``abcdefg``. 

Could it be the password we are looking for ? Let's try it:
```bash
level01@SnowCrash:~$ su flag01
Password: 
Don't forget to launch getflag !
```

### Retrieving the flag

```bash
flag01@SnowCrash:~$ getflag
  Check flag.Here is your token : f2av5il02puano7naaf6adaaf
```

```bash
flag01@SnowCrash:~$ su level02
Password: 
level02@SnowCrash:~$ 
```

And exactly as the previous level, it worked! And we are now in the **level02**

</details>

## level02

<details>

<summary>Explanations</summary>

##

For the level02, we get a file for the first time:
```bash
level02@SnowCrash:~$ ls
level02.pcap
```

``level02.pcap`` is a pcap (packet capture) file and is used to capture a network traffic

The file itself is unreadable, using ``cat`` is useless **HOWEVER**, if we can the file and look at the output, we can find an interesting line:
```
Password: Nf&NatB'̊$E4��@@J-;���;��ߙO/Y�{���%�s��
```

It is of course not humanly readable, but now we know that the password we are looking for is in this file! We now need to find a way of reading it.

To proceed, we will be using [TShark](https://tshark.dev/), a terminal version of WireShark (our ``tshark`` package is built outside of the VM in a Dockerfile with an entrypoint ``tshark``).

TShark offers a bunch of ways to gather informations in pcap files. What interest us here is the flag ``-z follow,prot,mode,filter[,range]``. It lets us see the contents of a stream between 2 connections.

``prot`` specifies the protocol like TCP, UDP, SSL

``mode`` specifies the output mode like ASCII, HEX, RAW

``filter`` specifies the stream to be displayed

In our case, the protocol is TCP, we want our output in HEX for easy read, and it will be really useful here

So now let's run the command:
```bash
➜  level02 git:(main) ✗ docker run tshark:latest -r level02.pcap -qz follow,tcp,hex,0
Running as user "root" and group "root". This could be dangerous.

===================================================================
Follow: tcp,hex
Filter: tcp.stream eq 0
Node 0: 59.233.235.218:39247
Node 1: 59.233.235.223:12121
        00000000  ff fd 25                                          ..%
...
        0000007E  0d 0a 4c 69 6e 75 78 20  32 2e 36 2e 33 38 2d 38  ..Linux  2.6.38-8
        0000008E  2d 67 65 6e 65 72 69 63  2d 70 61 65 20 28 3a 3a  -generic -pae (::
        0000009E  66 66 66 66 3a 31 30 2e  31 2e 31 2e 32 29 20 28  ffff:10. 1.1.2) (
        000000AE  70 74 73 2f 31 30 29 0d  0a 0a 01 00 77 77 77 62  pts/10). ....wwwb
        000000BE  75 67 73 20 6c 6f 67 69  6e 3a 20                 ugs logi n:
000000B2  6c                                                l
        000000C9  00 6c                                             .l
000000B3  65                                                e
        000000CB  00 65                                             .e
000000B4  76                                                v
        000000CD  00 76                                             .v
000000B5  65                                                e
        000000CF  00 65                                             .e
000000B6  6c                                                l
        000000D1  00 6c                                             .l
000000B7  58                                                X
        000000D3  00 58                                             .X
000000B8  0d                                                .
        000000D5  01                                                .
        000000D6  00 0d 0a 50 61 73 73 77  6f 72 64 3a 20           ...Passw ord:
000000B9  66                                                f
000000BA  74                                                t
000000BB  5f                                                _
000000BC  77                                                w
000000BD  61                                                a
000000BE  6e                                                n
000000BF  64                                                d
000000C0  72                                                r
000000C1  7f                                                .
000000C2  7f                                                .
000000C3  7f                                                .
000000C4  4e                                                N
000000C5  44                                                D
000000C6  52                                                R
000000C7  65                                                e
000000C8  6c                                                l
000000C9  7f                                                .
000000CA  4c                                                L
000000CB  30                                                0
000000CC  4c                                                L
000000CD  0d                                                .
        000000E3  00 0d 0a                                          ...
        000000E6  01                                                .
        000000E7  00 0d 0a 4c 6f 67 69 6e  20 69 6e 63 6f 72 72 65  ...Login  incorre
        000000F7  63 74 0d 0a 77 77 77 62  75 67 73 20 6c 6f 67 69  ct..wwwb ugs logi
        00000107  6e 3a 20                                          n:
===================================================================
```

Executing this command reveals an interesting string: ``ft_wandr...NDRel.L0L.``.

While this looks like a password, a closer inspection of the hexadecimal output shows that the dots ``.`` correspond to the value ``7f``. In ASCII, ``0x7f`` represents the ``DEL`` (Delete) control character, not a literal dot.

By interpreting each ``7f`` as a backspace, we can reconstruct the actual password: ``ft_waNDReL0L``. The final character (a dot again), ``0x0d``, is a Carriage Return, indicating the user pressed ENTER.

### Authentication

Now, let's try it:
```bash
level02@SnowCrash:~$ su flag02
Password: 
Don't forget to launch getflag !
```

It worked! So now let's get the flag

### Retrieving the flag
```bash
flag02@SnowCrash:~$ getflag
Check flag.Here is your token : kooda2puivaav1idi4f57q8iq
```

```bash
flag02@SnowCrash:~$ su level03
Password: 
level03@SnowCrash:~$ 
```

The flag is valid! So let's go on the next level

</details>

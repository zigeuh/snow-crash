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

After ``john`` did its work, we can observe something very interesting: ``abcdefg``. Could it be the password we are looking for ? Let's try it:
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

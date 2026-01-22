# snow-crash

## level00

### Finding first hints

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

## level01

For this **level01**, we can, in first place try, to find eventually files owned by flag01, like we did previously:
```bash
level01@SnowCrash:~$ find / -user flag01 2> /dev/null
level01@SnowCrash:~$ 
```

Nothing was found. We are starting from scratch.

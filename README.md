# snow-crash

## level00

For the level00, nothing relevant is provided in the /home/user/level00 directory. So what we are going to do is taking a look at every files of the computer that could be used by the user flag00 that we are trying to log on. To do so, we are going to use the find command. In our case:

```bash
find / -user flag00 2> /dev/null
```

We added the error redirection **2> /dev/null** to block all errors from being displayed.
With this command, we get 2 outputs:

```bash
/usr/sbin/john
/rofs/usr/sbin/john
```

It is files, so we can cat them. And when doing that we get this output for both: **cdiiddwpgswtgt**

If we try connecting to the flag00 user with this, we get that error:

```bash
level00@SnowCrash:~$ su flag00
Password: 
su: Authentication failure
```

This means that this is not the password we are looking for. On the other hand, maybe we can do something with that.
So what we are going to try is to probably decrypt it.
To do so, we are going to use the french website [dcode](https://www.dcode.fr/) since this website gives us a very effective [Cipher Identifier](https://www.dcode.fr/cipher-identifier)
With this tool, we can see few ciphers than may have been used to encrypt the password.
8 of them have the best results, and actually 4 of them shows **nottoohardhere**:
- Affine Cipher
- Disk Cipher
- ROT Cipher
- Caesar Cipher

We might not know all ciphers, we at least know the Caesar Cipher that consists in shifting letters a certain amount of time. For a shift of 1 on the left, A becomes B, B becomes C, ..., and Z becomes A.
In our case, **cdiiddwpgswtgt** is a right shift of 15.

So now that we have **nottoohardhere**, we can try to log on the flag00 user:
```bash
level00@SnowCrash:~$ su flag00
Password: 
Don't forget to launch getflag !
flag00@SnowCrash:~$
```

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
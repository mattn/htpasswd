# htpasswd

Re-write of htpasswd in Go

## Usage

```
Usage:
        htpasswd [-cimBdpsDv] [-C cost] passwordfile username
        htpasswd -b[cmBdpsDv] [-C cost] passwordfile username password

        htpasswd -n[imBdps] [-C cost] username
        htpasswd -nb[mBdps] [-C cost] username password
 -c  Create a new file.
 -n  Don't update file; display results on stdout.
 -b  Use the password from the command line rather than prompting for it.
 -i  Read password from stdin without verification (for script usage).
 -m  Force MD5 encryption of the password (default).
 -B  Force bcrypt encryption of the password (very secure).
 -C  Set the computing time used for the bcrypt algorithm
     (higher is more secure but slower, default: 5, valid: 4 to 31).
 -d  Force CRYPT encryption of the password (8 chars max, insecure).
 -s  Force SHA encryption of the password (insecure).
 -p  Do not encrypt the password (plaintext, insecure).
 -D  Delete the specified user.
 -v  Verify password for the specified user.
On other systems than Windows and NetWare the '-p' flag will probably not work.
The SHA algorithm does not use a salt and is less secure than the MD5 algorithm.
```

## Installation

```
$ go get github.com/mattn/htpasswd
```

## License

MIT

## Author

Yasuhiro Matsumoto (a.k.a. mattn)

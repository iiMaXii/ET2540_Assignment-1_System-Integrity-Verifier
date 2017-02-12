# ET2540 Assignment 1 System Integrity Verifier
A simple system integrity verifier written in Python. It detects changes in a Unix filesystem.

This is an assignment was part of the course Network Security at Blekinge Institute of Technology.

## Example
### Usage
```
$ ./siv.py
usage: siv.py [-h] (-i | -v) -D MONITORED_DIRECTORY -V VERIFICATION_FILE -R
              REPORT_FILE [-H {sha224,sha512,sha1,sha256,md5,sha384}]
```

### Initiation
```
$ ./siv.py -i -D /var/log -V db.csv -R report_1.txt -H sha1
```

### Verification
```
$ ./siv.py -v -D /var/log -V db.csv -R report_2.txt
```

### Limitations
* The program cannot detect when a file has been moved, instead the program shows this as a file deleted and file added.

IntegriDB: Verifiable SQL for Outsourced Database.
====================================================
Build instructions.
----------------------------------------------------
IntegriDB relies on the following libraries:
- mysql server as SQL database server.
- mysql client c++ libraries as SQL API.
- openssl for encryptions and hashing.
- ate-paring for bilinear groups. https://github.com/herumi/ate-pairing.
- xbyak. https://github.com/herumi/xbyak.
- ntl and gmp for doing number theory.

For example, on a fresh Ubuntu 14.04, install the following packages:
- ```$ sudo apt-get install build-essential git libgmp3-dev libprocps3-dev libgtest-dev python-markdown libboost-all-dev libssl-dev libmysqlclient-dev mysql-server mysql-client```
- Download and install xbyak from https://github.com/herumi/xbyak to the same directory as IntegriDB. (Go to xbyak/ and $ sudo make install.)
- Download ate-pairing from https://github.com/herumi/ate-pairing to the same directory as IntegriDB. (Go to ate-pairing/ and $ make.)
- Download and install ntl library. http://www.shoup.net/ntl/ and http://www.shoup.net/ntl/doc/tour-unix.html

To run the code,
- The default connection settings for mysql in client.cpp is username: root, password: root, database name: integridb. Change according to your settings. (Remember to create a database in mysql.)
- Set the header and lib path to include ate-pairing (if ate-pairing/ is located at /home/ubuntu/): 
```
    $ CPLUS_INCLUDE_PATH=/home/ubuntu/ate-pairing/include/ 
    $ export CPLUS_INCLUDE_PATH
    $ LIBRARY_PATH=/home/ubuntu/ate-pairing/lib/
    $ export LIBRARY_PATH
```
- In interidb/, 
``` 
    $ make main 
    $ ./main
```

Please adjust the paths in Makefile according to the settings on your machine. The default setting assumes integridb/ and ate-pairing/ are located at /home/ubuntu/

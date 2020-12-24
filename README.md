# Final Project

Weifan Jiang (wj2301@columbia.edu)<br />
Haotang Liu (hl3311@columbia.edu)<br />
Yuan Xu (yx2537@columbia.edu)

## Install

1. Setting up the ca: run `./setupca.sh`
2. Under `CAserver` folder
   1. Run `./setcaserverkeypair.sh`
   2. Run `make`
3. Under `server` folder, 
   1. Run `./setmailserverkeypair.sh`
   2. Run `make`
4. Under `client` folder
   1. Run `./getcacert.sh`
   2. To install a client for a user, run `make install USER=<username>`. For example, run `make install USER=overrich` to get a client for `overrich`. There will be a `client-overrich` under the parent folder. Create more than 1 client for testing.
   
Note: the `CAserver/config`, `server/config` and `client/config` files contain the ip addresses and port
numbers that each component hosts on and/or connects to. The current configurations allow three components
to run on one VM. If need to run on separate VMs, it is necessary to change the configuration files with
appropriate ip addresses and port numbers, and the ip/port for the same component in different files
must match.

## Design

### sandboxing

The program is divided into three components: client, mailing server, and CA server. The client sends requests
to mailing server, and mailing server sends request to CA server for password verification and certificate
generation. The three components are designed to be placed on separate VMs and communicate with HTTPS. The
list of users and hashed passwords are stored with the CA. This architecture ensures that if the mailing
server is compromised, the passwords and the CA private key will not leak.

### encryption/decryption

The general idea of our mail encryption/decryption and authenticity verification:
- We use the symmetric encryption algorithm to encrypt/decrypt messages since: 
  - symmetric algorithm is faster
  - OpenSSL does not support asymmetric algorithm over large files.
- We encrypt the key for the symmetric algorithm using the recipient's public key to utilize the advantage of the asymmetric encryption algorithm. Thus the recipient could decrypt it using its private key.
- For each <sender, recipient> pair, we maintain a unique id for every message. This pair could prevent the server from delivering the same one-time message to the sender again and again.
- For authenticity verification, the sender will sign the mail using its private key while the recipient will verify it using the sender's public key. Thus, we include the sender's client certificate in our mail, which will indicate the sender's identity and generate its public key. This sender's certificate also needs to be encrypted. Otherwise, chances could be that someone else (for example, the server) substitutes its certificate and the mail's signature, and the recipient cannot sense it.
- To sum up, our mail include 3 parts: (a) encrypted key (b) [id | encrypt(cert | msg)] (c) sign( [id | encrypt(cert | msg)] ). When receiving a mail, the receiver first decrypts the key for encryption, decrypts the sender's cert and message, and finally checks the id for this mail and verifies the signature.

The login logic of users using its client certificate:
- The user sends its certificate to the server. The server could verify the authenticity of the certificate by comparing it with the one it previously recorded.
- The server encrypts a random number using the public key obtained from the cert and sends it to the user to confirm that the user is the one who actually holds the certificate.
- Only those with the corresponding private key could decrypt the number correctly, which means the user could verify its authenticity by sending the correct original random number to the server.

## File layout

## File permission decisions

On the CA side, the passwords are saved as `user_passwords.txt`, and the executable `CAserver` hosts a
HTTPS server and handles requests from the mailing server.

The permission of `user_passwords.txt` is set as follows:

```
-rw-rw---- 1 root CAserver_D6ijQa 4123 Dec 24 04:43 user_passwords.txt
```

The permission of the `CAserver` executable is set as follows:

```
-rwxrwsr-x 1 wj2301 CAserver_D6ijQa 171112 Dec 24 04:43 CAserver
```

The group name `CAserver_D6ijQa` is randomly generated when setting up the server. These permission settings
ensure that on the VM which the CA is hosted on,  only the CA server application and root can read and modify
the password database.

## Testing

1. Under `CAserver` folder
   1. Run `./CAserver`
2. Under `server` folder, 
   1. Run `./server`
3. Install two clients: overrich and unrosed
4. Generate certificates for the two users:
   1. Under `client-overrich`, run `./getcert overrich Freemasonry_bruskest`
   2. Under `client-unrosed`, run `./getcert unrosed shamed_Dow`
5. Send message from `overrich` to `unrosed`
   1. Under `client-overrich`, run `./sendmsg unrosed test.txt`
   2. Under `client-unrosed`, run `./recvmsg`

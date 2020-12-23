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
   1. Run `getcacert.sh`
   2. To install a client for a user, run `make install USER=<username>`. For example, run `make install USER=overrich` to get a client for `overrich`. There will be a `client-overrich` under the parent folder. Create more than 1 client for testing.

## Design

## File layout

## File permission decisions

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

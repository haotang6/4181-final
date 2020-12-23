#!/bin/bash

# add a group that has access to the user passwords
random="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 6 | head -n 1)"
groupname="CAserver_$random"
grep -E -i "^$groupname" /etc/group;
while [ $? -eq 0 ]
do
  random="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 6 | head -n 1)"
  groupname="CAserver_$random"
  grep -E -i "^$groupname" /etc/group;
done
addgroup --force-badname "$groupname"

chown root user_passwords.txt
chgrp "$groupname" user_passwords.txt
chmod u=rw,g=rw,o= user_passwords.txt

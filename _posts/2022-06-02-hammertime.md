---
title: Hammertime Commands
permalink: hammertime/
date: 2022-06-02 10:00:00 -500
---
---
The following are the commands that have worked for me with the tool Hammertime.

### Connect using a specific port.
```sh
$ ht login --ssh-port=PORT IP_OR_TICKET
```

### How to run commands as root.
```sh
$ ht --quiet command --root --command "date" IP_OR_TICKET
```

### How to run command as root in a specific port.
```sh
$ ht --quiet command --root --command "date" --ssh-port=PORT IP_OR_TICKET
```

### Search for Rackers:
```sh
$ ht racker --search "Racker_Name"
$ ht racker --detailed --search "Racker_Name"
```

### Check all checks in cloud servers
```sh
$ ht cloud-monitoring --show-config IP_OR_TICKET
```

### Check for cloud servers info.
```sh
$ ht --cloud-account ACCOUNT info -I IP_OR_TICKET | grep OS
```

### How to Check OS version
```sh
$ ht --quiet command --root --command "egrep '^(VERSION|NAME)=' /etc/*release;" IP_OR_TICKET
```

### User Creation

#### Only user
```sh
$ ht --quiet command --root --command "useradd USER; 'USER:PWD' | chpasswd; chage -l USER" IP_OR_TICKET
```

#### Super User
```sh
$ ht --quiet command --root --command "USER='USER'; PWD='PWD'; useradd -c 'Created as per TICKET' \${USER}; echo 'USER:\${PWD}' | chpasswd; chage -l \${USER} | head -1; getent passwd \${USER}; echo -e '\n#Ticket TICKET\nUSER ALL=(ALL) ALL' >> /etc/sudoers; tail -2 /etc/sudoers; sudo -l -U \${USER} | tail -2; visudo -c;" IP_OR_TICKET
```

### Add user to sudoers
```sh
$ ht --quiet command --root --command "echo -e '\n#Ticket TICKET\nUSER  ALL=(ALL) ALL' >> /etc/sudoers; tail -2 /etc/sudoers; sudo -l -U adm_kala" IP_OR_TICKET
```

### Password Reset and GECOS field change

#### With passwd
```sh
$ ht --quiet command --root --command "USER='USER'; PWD='PWD'; echo '\${PWD}' | passwd --stdin \${USER}; chage -l \${USER} | head -2; usermod -c  'USER_NAME - TICKET' \${USER};" IP_OR_TICKET
```

#### With chpasswd
```sh
$ ht --quiet command --root --command "USER='USER'; PWD='PWD'; echo '\${USER}:\${PWD}' | chpasswd; chage -l \${USER} | head -2; usermod -c  'USER_NAME - TICKET' \${USER};" IP_OR_TICKET
```

### Check if MySQL is running
```sh
$ ht --linuxonly -C "ps aux| grep mysql" IP_OR_TICKET --sudo
```

### How to get an user in Linux devices.

#### How to only get local users in Linux
```sh
$ eval getent passwd {$(awk '/^UID_MIN/ {print $2}' /etc/login.defs)..$(awk '/^UID_MAX/ {print $2}' /etc/login.defs)};
```

#### With Hammertime
```sh
$ ht --quiet command --root --command "eval getent passwd {$(awk '/^UID_MIN/ {print $2}' /etc/login.defs)..$(awk '/^UID_MAX/ {print $2}' /etc/login.defs)};" IP_OR_TICKET
```

### Getent & MySQL

#### Only Local Users
```sh
$ ht --quiet command --root --command "USER='USER'; getent passwd | grep -iE \${USER};" IP_OR_TICKET
```

#### Only MySQL Users
```sh
$ ht --quiet command --root --command "mysql --defaults-file=/root/.my.cnf -e 'select user,host from mysql.user;' " IP_OR_TICKET
```

#### Getent and MySQL
```sh
$ ht --quiet command --root --command "USER='USER'; getent passwd | grep -iE \${USER};' | grep -iE \${USER}" IP_OR_TICKET 
```

#### All users
```sh
$ ht --quiet command --root --command "getent passwd;mysql --defaults-file=/root/.my.cnf -e 'select user,host from mysql.user;' " IP_OR_TICKET
```

#### Specific user
```sh
$ ht --quiet command --root --command "USER='USER'; getent passwd | grep -iE \${USER}; mysql --defaults-file=/root/.my.cnf -e 'select user,host from mysql.user;' | grep -iE \${USER}" IP_OR_TICKET
```

### How to lock an user in Linux devices.
- Password lock
- Password status
- Gecos Field
- Getent

```sh
$ ht --quiet command --root --command "USER='USER'; passwd -l \${USER}; chage -E0 \${USER}; passwd --status \${USER}; usermod -c 'Disabled as per TICKET' \${USER}; usermod -s /bin/false \${USER}; getent passwd \${USER};" IP_OR_TICKET
```

### List all sudo users.
```sh
$ ht --quiet command --root --command "getent passwd | cut -f1 -d: | sudo xargs -L1 sudo -l -U | grep -v 'not allowed' | grep -i -A1 'run the following commands'" IP_OR_TICKET
```

### Check Nimbus Hub for UIM purposes.
```sh
$ ht command --root --command "egrep 'hub\ ' /opt/nimsoft/robot/robot.cfg" IP_OR_TICKET
```

### How to print only IPs for specific devices using Hammertime
```sh
$ ht --hide-passwords info IP_OR_TICKET | egrep -i "Login IP" | $ awk '{print $3}'
```

### How to scan a range of IPs using Hammertime.
```sh
$ ht --hide-passwords info IP_OR_TICKET | egrep -i  "Login IP" | awk '{print $3}' > scan.txt
```

### How to share files with Hammertime
```sh
# Locally to Server
$ ht --quiet copy --src local_path --dest device:path

# Server to Local
$ ht --quiet copy --src device:path --dest local_path

# Server to Server
$ ht --quiet copy --src device:path --dest device:path
```

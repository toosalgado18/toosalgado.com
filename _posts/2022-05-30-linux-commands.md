---
title: Helpful Linux Commands
date: 2022-05-30 08:00:00 -600
lastmod: 2023-09-09 -500
permalink: linux-commands/
---
---
This is a list of useful commands that have worked for me over the years for multiple servers while I was working at RXT..

## Apache / NGINX Commands

### Modify apache to redirect from http to https
In the 80 vhost block add the following lines:

```apache
RewriteEngine On 
RewriteCond %{HTTPS} off 
RewriteRule (.*) https://%{SERVER_NAME}/$1 [R,L]
```

### How to Check Apache Memory Usage:

```sh
$ ps aux | grep 'httpd' | awk '{print $6/1024 " MB";}'
```

### How to find for private keys in server

```sh
$ find /var/www/ -type f -iname "*.key" | grep -i domain
```

### Check for permissions in a Document Root
```sh
$ find /var/www/vhosts/example.com/ -ls | awk '//{print $3,$5,$6}' | sort -u
```

### Check the Database connections using the apache logs
```sh
$ cat /var/log/httpd/*log | egrep POST | awk '{print $1,$6,$7}' |sort -n | uniq -c | sort -rn | head -50
```

### Function: NGINX Equivalent of HTTPD -S
```sh
$ nginx -T |grep -P '(%.conf|configuration|server_name|listen)' | grep -v ::
or
$ curl -s nginxctl.rax.io | python - -S
```

### Get code numbers for websites:
```sh
$ grep -vE '200|301|302|400|404' /var/log/apache2/*access*log | sort -k 7 | cut -d ' ' -f 9 | sort -nr | uniq -c | head
or
$ grep -vE '200|301|302|400|404' /var/log/httpd/*access*log | sort -k 7 | cut -d ' ' -f 9 | sort -nr | uniq -c | head
```

### Disabling TLS Versions prior to 1.2
```sh
# Check the compatible versions
nmap --script ssl-enum-ciphers -p 23.253.153.39 | grep -E "TLSv|SSLv"
```
```apache
# Add the following into the vhost configuration file.
# Allow only TLS 1.2 
SSLCipherSuite HIGH:!aNULL
SSLHonorCipherOrder on
SSLProtocol -all +TLSv1.2

# We can allow only TLS 1.3
SSLCipherSuite HIGH:!aNULL
SSLHonorCipherOrder on
SSLProtocol -all +TLSv1.3

# Allow both TLS 1.2 and TLS 1.3
SSLCipherSuite HIGH:!aNULL
SSLHonorCipherOrder on
SSLProtocol -all +TLSv1.2 +TLSv1.3
```
```sh
$ systemctl restart httpd
or
$ systemctl restart apache2
```

### How to check the SSL of a website with cURL or OpenSSL
```sh
$ URL='WEBSITE'; curl --insecure -v https://${URL} 2>&1 | awk 'BEGIN { cert=0 } /^\* Server certificate:/ { cert=1 } /^\*/ { if (cert) print }'
or
$ URL='WEBSITE';  curl --insecure -v https://${URL}  2>&1 | awk 'BEGIN { cert=0 } /^\* SSL connection/ { cert=1 } /^\*/ { if (cert) print }'
```

### How to check the SSL of a website from a server using cURL or OpenSSL.
```sh
$ URL='WEBSITE' IP='IP'; curl -svo /dev/null --insecure https://${URL}  --resolve ${URL}:443:${IP} 2>&1 | awk 'BEGIN { cert=0 } /^\* SSL connection/ { cert=1 } /^\*/ { if (cert) print }'
or
$ URL='WEBSITE'; IP='IP'; openssl s_client -connect ${IP} -servername https://${URL} 2>/dev/null | openssl x509 -text -noout | grep -i "dns\|before\|after"
```

### Do a curl internally from a server.
```sh
$ URL='WEBSITE'; curl -ILks http://${URL} --resolve ${URL}:80:localhost
$ URL='WEBSITE'; curl -ILks http://${URL} --resolve ${URL}:80:127.0.0.1
$ URL='WEBSITE'; IP='IP'; curl -Lk http://${URL} --resolve ${URL}:80:${IP}
```

### How to cURL using a username (useful for PHPMyAdmin)
```sh
$ URL='WEBSITE'; curl -ILk -u USER http://${URL} --resolve example.com:80:localhost
$ URL='WEBSITE'; curl -ILk -u USER http://${URL} --resolve example.com:80:127.0.0.1
$ URL='WEBSITE'; IP='IP' curl -ILk -u USER http://${URL} --resolve example.com:80:${IP}
```

## MySQL Commands

### Check Replication status
```sh
mysql -se "SHOW SLAVE STATUS\G" | egrep 'Running|Seconds|Error'
```

### How to check the processes from mysql
```sql
SHOW PROCESSLIST;
```

### Check if slow query is enabled in MYSQL
```sql
show global variables like 'slow_query_log';
```

### Whitelisting and Creating user for MySQL DB
```sql
GRANT ALL ON *.* TO 'userexample'@'localhost' IDENTIFIED BY 'PASSWORD';
```

### Change MariaDB root password
```sql
UPDATE mysql.user SET authentication_string = PASSWORD('MyNewPassword') WHERE User = 'root';
```

### Changing password in WordPress
```sql
USE DB_NAME;
SHOW tables LIKE '%users';
SELECT ID,user_login,user_pass FROM wp_users;
UPDATE wp_users SET user_pass = MD5('PASSWORD') WHERE ID = 1;
```

### Enable Logs in MySQL
https://www.a2hosting.com/kb/developer-corner/mysql/enabling-the-slow-query-log-in-mysql

```sql
-- Check if they are enabled
show variables like '%slow_query%';
show variables like '%general_%';
-- Test if it is working
SELECT SLEEP(X);
```

## PHP Commands

### PHP INFO Script
```sh
$ echo "<?php phpinfo(); ?>" > phpinfo.php'
$ curl -IL /phpinfo.php
```

### PHP Configuration File
```sh
$ php -i | grep "Loaded Configuration File"
```

# Plesk Commands:

### Check the license of Plesk.
```sh 
$ plesk bin keyinfo -l | egrep "plesk_key_id|lim_dom:"
```

### How to enable secure server with Plesk
```sh
# Update TLS Protocol
$ plesk bin server_pref -u -ssl-protocols 'TLSv1.2'
SUCCESS: Server preferences are successfully updated 
 
# Update SSL Ciphers
$ plesk bin server_pref -u -ssl-ciphers 'ECDH+AESGCM:ECDH+CHACHA20:ECDH+AES256:!aNULL:!MD5:!DSS:!SHA1' 
SUCCESS: Server preferences are successfully updated 
 
# Check for TLS version and Ciphers.
$ egrep "SSLProtocol|SSLCipherSuite" /etc/httpd/conf.d/ssl.conf | grep -v "#" 
SSLProtocol +TLSv1.2 
SSLCipherSuite ECDH+AESGCM:ECDH+CHACHA20:ECDH+AES256:!aNULL:!MD5:!DSS:!SHA1
```

### Enabling HTTP/2 in Plesk
```sh
$ plesk bin http2_pref enable
$ curl -sI https://WEBSITE
```

## OS Commands:

### Check if Sophos is installed
```sh
$ ps faux | grep sav; /opt/sophos-av/bin/savdstatus
```

### Check if nimbus is running
```sh
$ ps -fea | grep nimbus`
```

### Check Nimbus threshold for proc_queue_lenght,
```sh
$ vim /opt/nimsoft/probes/system/cdm/cdm.cfg
$ sed -n '/<proc_q_len>/,/<\/proc_q_len>/p' /opt/nimsoft/probes/system/cdm/cdm.cfg
$ systemctl restart nimbus; sleep 15s; systemctl status nimbus
```

### Journal Control Useful commands
```sh
$ journalctl --since today
$ journalctl -o verbose
```

#### To check on a service
```sh
$ journalctl _SYSTEM_UNIT=sshd.service
```

#### To check on only priority warning or above
```sh
$ journalctl -p warning
```

#### All msgs form the previous 10 mins
```sh
$ journalctl --since 08:05:00 --until 08:13:00
```

#### Events originated from the sshd service since specific time
```sh
$ journalctl --since 07:10:00 _SYSTEMD_UNIT="sshd.service"
```

#### Check when was the last time it ran.
``` sh
$ journalctl | head -2
```

### How to check the IP
```sh
$ curl -4 icanhazip.com
```

### How to check the Public IP of an interface in a server
```sh
$ curl --interface IP icanhazip.com
```

### IPTables:

#### Checking if an IP is block in IPTABLES, Check if IP is blocked:
```sh
$ iptables -L -n –line | grep [IP Address]
```

### If IP appear as DROP or REJECT, the IP has been blocked

### Unblock the IP Address
``` sh
$ iptables -I INPUT -s [IP Address] -j ACCEPT
```

### Blocking back an IP Address
```sh
$ iptables -A INPUT -d [IP Address] -j DROP
$ service iptables save
```

### How to change expiration date in a linux server:

https://www.thegeekstuff.com/2009/04/chage-linux-password-expiration-and-aging/

To turn off the password expiration for an user account, set the following:
- m 0 will set the minimum number of days between password change to 0
- M 99999 will set the maximum number of days between password change to 99999
- I -1 (number minus one) will set the “Password inactive” to never
- E -1 (number minus one) will set “Account expires” to never.

```sh
$ chage -m 0 -M 99999 -I -1 -E -1 USER
```

Or to set to +n days
```sh
$ sudo chage -E `date -d '+90 days' +%F`USER
```

### How to check CPU for the last month
```sh
# Detailed
$ for file in /var/log/sa/sa[0123456789][0123456789]; do echo -e "---\n$(ls -la $file | awk '{print $7, $6}')"; sar -u -f "$file" | head -3 | tail -1 | sed 's/00\:00\:\0[012]/\t/'; sar -u -f "$file" | awk 'NR==1; END{print}' | grep Average; done

# Summarized
$ echo -e "Date:\t\t Avg CPU Idle%:"; for file in /var/log/sa/sa[0123456789][0123456789]; do sar -f "$file" | awk 'NR==1; END{print}' | awk 'NR%2 != 0 { print $4 }; NR%2 == 0 { print $8}' | sed -e '/22/N;s/\n/ \t /';done
```

### How to check Load Average for the last month
```sh
# Detailed
$ for file in /var/log/sa/sa[0123456789][0123456789]; do echo -e "---\n$(ls -la $file | awk '{print $7, $6}')"; sar -q -f "$file" | head -3 | tail -1 | sed 's/00\:00\:\0[012]/\t/'; sar -q -f "$file" | awk 'NR==1; END{print}' | grep Average; done

# Summarized
$ echo -e "Date:\t\t Load Avg 1,5,15:"; for file in /var/log/sa/sa[0123456789][0123456789]; do sar -q -f "$file" | awk 'NR==1; END{print} '| awk 'NR%2 != 0 { print $4 }; NR%2 == 0 { print $4, $5, $6}' | sed -e '/22/N;s/\n/ \t /';done
```

### How to check Memory Utilization for the last month
```sh
# Detailed
$ for file in /var/log/sa/sa[0123456789][0123456789]; do echo -e "---\n$(ls -la $file | awk '{print $7, $6}')"; sar -r -f "$file" | head -3 | tail -1 | sed 's/00\:00\:\0[012]/\t/'; sar -r -f "$file" | awk 'NR==1; END{print}' | grep Average; done
```

### How to check Load Average and then CPU for a specific time
```sh
$ sar -q -s 14:00:00 -e 15:00:00
$ sar -u -s 14:00:00 -e 15:00:00
```

### How to user activity in logs
```sh
$ egrep -r '(login|attempt|auth|success):' /var/log
```

### Check Fail2Ban logs
```sh
$ tail /var/log/fail2ban.log
```

### How to get CORS header response.
```sh
$ URL='WEBSITE' curl -H "Access-Control-Request-Method: GET" -H "Origin: http://localhost" --head http:${URL}
```

### How to check CPU and MEM consumption with a custom PS command.
```sh
$ ps -eo pid,pcpu,pmem,comm,user,time --sort=-time,-pcpu,-pmem | head
```

### Check for ports Open
```sh
$ lsof -nP -iTCP -sTCP:LISTEN
or
$ netstat -tulpn
```

### Test if a port is open
```sh
$ ls | nc -l -p 22
```

### How to check if someone rebooted the server with history
```sh
$ grep reboot /home/*/.bash_history
```

### How to take out blank lines with grep.
```sh
$ egrep -v -e '^$'  
$ egrep -v "^(\r?\n)?$" 
$ egrep -v "^[[:space:]]*$"
```

### How to check if a user is locked via PAM
```sh
$ pam_tally2 --user=USER
```

### How to check with nmap if IP/Server is up.
```sh
$ nmap -sn -oG - -v IP
$ nmap -sn -oG - -v -iL hosts_to_scan.txt
```

### How to check all cron jobs for all users.

#### Exclude comments and suppress 'no crontab for user...' messages:
```sh
$ for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null | grep -v '^#'; done
```

#### To not exclude messages.
```sh
$ for user in $(getent passwd | awk -F : '{print $1}'); do echo $user; crontab -u $user -l; done
```

### How to check for inodes usage under a directory.
```sh
$ find /tmp -xdev -maxdepth 1 -type d | while read i;do echo -ne "Inodes for ${i}:\t";find ${i} -xdev | wc -l;done
```

### How to secure WordPress
```apache
<IfModule mod_rewrite.c> 
RewriteEngine On 
ServerSignature Off 
RewriteRule ^.*/install.php$ - [NC,R=404,L] 
RewriteRule ^.*/xmlrpc.php$ - [NC,R=404,L] 

# Change IP Octets
RewriteCond %{REMOTE_ADDR} !^XX\.XX\.XX\.XX 
RewriteCond %{HTTP:X-Forwarded-For} !^XX\.XX\.XX\.XX 
RewriteRule ^/wp-login.php.* - [NC,R=404,L] 
</IfModule>
```

### How to generate a RSA 4096 SSH key
```sh
$ ssh-keygen -t rsa -b 4096 -C "USERNAME"
$ cat id_rsa.pub > /home/chroot/USERNAME/.ssh/authorized_keys
```
Then, share the private key.

### How to generate a RSA 2048 SSH key
```sh
$ ssh-keygen -t rsa -b 2048 -C "USERNAME"
$ cat id_rsa.pub > /home/chroot/USERNAME/.ssh/authorized_keys
```

Then, share the private key.

### How to look up for a directory by its name
```sh
$ find / -type d -name "dir-name-here" 2>/dev/null
```

### How to delete files that were created longer than 7 days ago
```sh
$ find . -type f -mtime +7 -delete
```

### Check for files exceeding certain amount of size
```sh
$ find / -type f -size +500M -exec ls -lh {} +
```

### Delete files and directories with find
```sh
$ find ~+ -type f -iname 'example' -ls -delete
$ find /path/of/dir -ls
```

### Check permissions in a directory
```sh
$ find /path -ls | awk '//{print $3,$5,$6}' | sort -u
```

### Change permissions to comply with WordPress security practices.
```sh
$ find /var/www/qrspace.com -type f -exec chmod 664 {} \+
$ find /var/www/qrspace.com -type d -exec chmod 2775 {} \+
```

### How to count largest files in a directory.
```sh
$ du -ahx / 2>/dev/null | sort -n -rh | head -n 20
```

### Check for the rhnsd service.
```sh
$ cat /etc/redhat-release; grep -A5 -F '<rhnsd>' /opt/nimsoft/probes/system/processes/processes.cfg;
```

### WHOIS Bulk Search.
```sh
$ host -t A WEBSITE
$ for ip in IPs; do whois $ip | echo "$ip $(grep 'OrgName')"; done
$ for ip in IPs; do whois $ip | echo "$ip $(grep 'Organization')"; done
```

### User Creation

#### SUDO User Script
```sh
UU='USER'; useradd ${UU};echo "${UU}:VidfyzknK3hyEkML" | chpasswd; chage -l ${UU} | head -1; usermod -c 'Created as per 211104-03107' ${UU}; getent passwd ${UU}; echo -e "${UU} ALL=(ALL) ALL" >> /etc/sudoers; tail -2 /etc/sudoers; sudo -l -U ${UU} | tail -2; visudo -c;
```

### How to list sudo users
```sh
$ for USER in $(cut -d: -f1 /etc/passwd); do sudo -U $USER -l | tail -3; done | grep -v 'not allowed'
```

### SFTP User Creation Script 1
```sh
chmod 711 /home/chroot/

User='USER'; \
ChrootDir='DIR'; \
TargetDir='/var/www/DIR'; \
Tkt='220601-ord-0001373'; \
useradd -d /home/chroot/${User} -s /sbin/nologin -G sftponly ${User}; \
echo "${User}:dqKVCaheT3P9FAsx" | chpasswd; \
chown root:root /home/chroot/${User}/; \
chmod 755 /home/chroot/${User}; \
mkdir -p /home/chroot/${User}/${ChrootDir}; \
chmod 755 /home/chroot/${User}/${ChrootDir}; \
chown ${User}:sftponly /home/chroot/${User}/${ChrootDir}; \
echo -e "#Ticket:${Tkt}\n${TargetDir}\t /home/chroot/${User}/${ChrootDir}\t none\t bind\t 0 0" >> /etc/fstab; \
mount /home/chroot/${User}/${ChrootDir};
```

### SFTP User Creation Script 2
```bash
# Define variables
User='USER'
ChrootDir='DIR'
TargetDir='/var/www/DIR'
Tkt='TICKET'

# Check if the user already exists
if id "${User}" &>/dev/null; then
  echo "User '${User}' already exists. Exiting."
  exit 1
fi

# Create the user with a secure password hash
useradd -d "/home/chroot/${User}" -s /sbin/nologin -G sftponly "${User}"
echo "${User}:$(openssl passwd -6 PASSWORD)" | chpasswd

# Set permissions for the user's home directory
chown root:root "/home/chroot/${User}"
chmod 755 "/home/chroot/${User}"

# Create the chroot directory and set permissions
mkdir -p "/home/chroot/${User}/${ChrootDir}"
chmod 755 "/home/chroot/${User}/${ChrootDir}"
chown "${User}:sftponly" "/home/chroot/${User}/${ChrootDir}"

# Add an entry to /etc/fstab and mount the directory
echo -e "#Ticket:${Tkt}\n${TargetDir}\t/home/chroot/${User}/${ChrootDir}\t none\t bind\t 0 0" >> /etc/fstab
if mount "/home/chroot/${User}/${ChrootDir}"; then
  echo "Mounted successfully."
else
  echo "Mounting failed. Please check the configuration."
fi
```

### SFTP Edit SSH config to allow users to only create files under 664 perms.
```sh
Subsystem     sftp   internal-sftp
Match Group sftponly
    PasswordAuthentication yes
    PubkeyAuthentication yes
    AuthorizedKeysFile .ssh/authorized_keys
    ChrootDirectory %h
    X11Forwarding no
    AllowTCPForwarding no
    ForceCommand internal-sftp -m 664 -u 0002
```

### Bonding Interface down
```sh
$ uptime -p; 
$ last | grep reboot -A2 -B2;
$ cat /proc/net/bonding/bond0;
$ ethtool bond0;
$ cat /etc/sysconfig/network-scripts/ifcfg-bond0
$ cat /var/log/messages | grep -i "bond0"
$ dmesg -T | grep bond0 -C4 | tail -20
```

### Check networking issues
```sh
$ ifconfig
$ ethtool -S interfaces
$ sar -n EDEV -s "07:00:00" -e "08:00:00"
$ sar -q -s "07:00:00" -e "08:00:00"
$ sar -r -s "07:00:00" -e "08:00:00"
```

### How to list packages from a disabled repo using yum.
```sh
$ yum --enablerepo=ius* list phpMyAdmin
```

### Parted usage
220211-05256
```sh
----------------------------
Expanded 380GB to an existing vDisk.
----------------------------
[root@server ~]# echo 1 > /sys/block/sdb/device/rescan
[root@server ~]# lsblk /dev/sdb                       
NAME              MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
sdb                 8:16   0  680G  0 disk 
└─sdb1              8:17   0  300G  0 part 
  └─vglocal01-u02 253:0    0  2.2T  0 lvm  /u02


[root@server ~]# parted /dev/sdb p
Error: The backup GPT table is not at the end of the disk, as it should be.  This might mean that another operating system believes the disk is smaller.  Fix, by moving the backup to the end (and removing the old backup)?
Fix/Ignore/Cancel? Fix
Warning: Not all of the space available to /dev/sdb appears to be used, you can fix the GPT to use all of the space (an extra 796917760 blocks) or continue with the current setting? 
Fix/Ignore? Fix                                                           
Model: VMware Virtual disk (scsi)
Disk /dev/sdb: 730GB
Sector size (logical/physical): 512B/512B
Partition Table: gpt
Disk Flags: 

Number  Start   End    Size   File system  Name     Flags
 1      1049kB  322GB  322GB               primary  lvm

[root@server ~]# parted -a optimal /dev/sdb
GNU Parted 3.1
Using /dev/sdb
Welcome to GNU Parted! Type 'help' to view a list of commands.
(parted) unit gb
(parted) p                                                                
Model: VMware Virtual disk (scsi)
Disk /dev/sdb: 730GB
Sector size (logical/physical): 512B/512B
Partition Table: gpt
Disk Flags: 

Number  Start   End    Size   File system  Name     Flags
 1      0.00GB  322GB  322GB               primary  lvm

(parted) mkpart primary 322GB 100%
(parted) set 2 lvm on                                                     
(parted) p                                                                
Model: VMware Virtual disk (scsi)
Disk /dev/sdb: 730GB
Sector size (logical/physical): 512B/512B
Partition Table: gpt
Disk Flags: 

Number  Start   End    Size   File system  Name     Flags
 1      0.00GB  322GB  322GB               primary  lvm
 2      322GB   730GB  408GB               primary  lvm

(parted) q                                                                
Information: You may need to update /etc/fstab.

----------------------------
Checking the newest partition.
----------------------------
[root@server ~]# lsblk /dev/sdb
NAME              MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
sdb                 8:16   0  680G  0 disk 
├─sdb1              8:17   0  300G  0 part 
│ └─vglocal01-u02 253:0    0  2.2T  0 lvm  /u02
└─sdb2              8:18   0  380G  0 part 
[root@server ~]# 

----------------------------
Managed LVM
----------------------------
[root@server ~]# pvcreate /dev/sdb2
  Physical volume "/dev/sdb2" successfully created.
[root@server ~]# vgextend vglocal01 /dev/sdb2
  Volume group "vglocal01" successfully extended
[root@server ~]# lvextend -r -l +100%FREE /dev/mapper/vglocal01-u02
  Size of logical volume vglocal01/u02 changed from 2.18 TiB (572412 extents) to 2.55 TiB (669691 extents).
  Logical volume vglocal01/u02 successfully resized.
resize2fs 1.42.9 (28-Dec-2013)
Filesystem at /dev/mapper/vglocal01-u02 is mounted on /u02; on-line resizing required
old_desc_blocks = 280, new_desc_blocks = 327
The filesystem on /dev/mapper/vglocal01-u02 is now 685763584 blocks long.

----------------------------
Checked the space after the expansion.
----------------------------

[root@server ~]# df -hP /u02
Filesystem                 Size  Used Avail Use% Mounted on
/dev/mapper/vglocal01-u02  2.6T  1.9T  607G  77% /u02
[root@server ~]# 
```

Or simplified

```sh
$ parted /dev/sdX mklabel gpt
$ parted -a optimal /dev/sdX mkpart primary 0% 100%
$ parted -s -- /dev/sdX mklabel gpt
$ parted -s -- /dev/sdX mkpart primary 2048s 100%
$ parted -s -- /dev/sdX set 1 lvm on
$ parted -s -- /dev/sdX align-check optimal 1
$ parted /dev/sdX unit s printnt


$ parted /dev/sdX p
Fix
Fix
$ parted -a optimal /dev/sdX
(parted) unit gb
(parted) mkpart primary XXXGB 100%
(parted) set X lvm on
(parted) p
(parted) q
$ kpartx -a /dev/sdX
$ lsblk /dev/sdX
$ pvcreate /dev/sdX
```

## Utilities

### Run a command from a vim file
```vim
:! command
```

### Copy and then paste a line with Vim.

```vim
yy # Copy 
p  # Paste
```

### Replace text with Vim.

```vim
:%s/example.com/example.org/g
```

### Add a comment to a whole block with Vim.

```
ctrl + v
Select all the lines you wish to comment out. 
Shift + i
Add the comment symbol #
ESC
```

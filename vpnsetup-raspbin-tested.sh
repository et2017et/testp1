
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
85
86
87
88
89
90
91
92
93
94
95
96
97
98
99
100
101
102
103
104
105
106
107
108
109
110
111
112
113
114
115
116
117
118
119
120
121
122
123
124
125
126
127
128
129
130
131
132
133
134
135
136
137
138
139
140
141
142
143
144
145
146
147
148
149
150
151
152
153
154
155
156
157
158
159
160
161
162
163
164
165
166
167
168
169
170
171
172
173
174
175
176
177
178
179
180
181
182
183
184
185
186
187
188
189
190
191
192
193
194
195
196
197
198
199
200
201
202
203
204
205
206
207
208
209
210
211
212
213
214
215
216
217
218
219
220
221
222
223
224
225
226
227
228
229
230
231
232
233
234
235
236
237
238
239
240
241
242
243
244
245
246
247
248
249
	
#!/bin/bash
# Kernel Sanders, MAR 2015
# Simple script for easy set up of L2TP over IPsec VPN on Debain based systems (tested on rasbian)
# Steps modified from: https://raymii.org/s/tutorials/IPSEC_L2TP_vpn_with_Ubuntu_14.04.html
 
# Must be root to run the script
if [ ! $UID = "0" ]; then
    echo "You must be root to run this script"
    exit 1
fi
 
# Get what we need for the VPN
apt-get install openswan xl2tpd ppp lsof rng-tools
 
# There is a bug in openswan 1:2.6.37-3+deb7u1 that causes it to fail with iOS devices
dpkg -l | grep openswan.*1:2.6.37-3+deb7u1 > /dev/null
if [ ! $? ]; then
    echo
    echo "[ERROR] the installed version of openswan is not compatable with OSX or iOS!"
    echo "Rolling back to the last stable openswan that works with iOS..."
    echo
    apt-get install openswan=1:2.6.37-3
    # if this fails, manually grab the deb from here for raspberry pi users 
    # http://snapshot.raspbian.org/201403301125/raspbian/pool/main/o/openswan/openswan_2.6.37-3_armhf.deb
fi
 
 
# Let our traffic through any iptables rules
echo
read -p "Enter the IP address of this box: " SERVERIP
iptables -t nat -A POSTROUTING -j SNAT --to-source $SERVERIP -o eth+
 
# Enable kernel IP packet forwarding and disable ICP redirects
if ! grep -P "^net.ipv4.ip_forward = 1" /etc/sysctl.conf > /dev/null; then
    echo "net.ipv4.ip_forward = 1" |  tee -a /etc/sysctl.conf
fi
if ! grep -Pv "^net.ipv4.conf.all.accept_redirects = 0" /etc/sysctl.conf > /dev/null; then
    echo "net.ipv4.conf.all.accept_redirects = 0" |  tee -a /etc/sysctl.conf
fi
if ! grep -P "^net.ipv4.conf.all.send_redirects = 0" /etc/sysctl.conf > /dev/null; then
    echo "net.ipv4.conf.all.send_redirects = 0" |  tee -a /etc/sysctl.conf
fi
if ! grep -P "^net.ipv4.conf.default.rp_filter = 0" /etc/sysctl.conf > /dev/null; then
    echo "net.ipv4.conf.default.rp_filter = 0" |  tee -a /etc/sysctl.conf
fi
if ! grep -P "^net.ipv4.conf.default.accept_source_route = 0" /etc/sysctl.conf > /dev/null; then
    echo "net.ipv4.conf.default.accept_source_route = 0" |  tee -a /etc/sysctl.conf
fi
if ! grep -P "^net.ipv4.conf.default.send_redirects = 0" /etc/sysctl.conf > /dev/null; then
    echo "net.ipv4.conf.default.send_redirects = 0" |  tee -a /etc/sysctl.conf
fi
if ! grep -P "^net.ipv4.icmp_ignore_bogus_error_responses = 1" /etc/sysctl.conf > /dev/null; then
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" |  tee -a /etc/sysctl.conf
fi
 
# Apply settings for other network interfaces
for vpn in /proc/sys/net/ipv4/conf/*; do echo 0 > $vpn/accept_redirects; echo 0 > $vpn/send_redirects; done
 
# Apply our changes
sysctl -p
 
# Don't blow out the backup if we are run again
if [ ! -f /etc/ipsec.conf.orig ]; then
    # Back up the original config for IPsec
    mv /etc/ipsec.conf /etc/ipsec.conf.orig
fi
 
# Write our config file
cat <<EOT > /etc/ipsec.conf
version 2 # conforms to second version of ipsec.conf specification
 
config setup
    dumpdir=/var/run/pluto/
    #in what directory should things started by setup (notably the Pluto daemon) be allowed to dump core?
 
    nat_traversal=yes
    #whether to accept/offer to support NAT (NAPT, also known as "IP Masqurade") workaround for IPsec
 
    virtual_private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12,%v6:fd00::/8,%v6:fe80::/10
    #contains the networks that are allowed as subnet= for the remote client. In other words, the address ranges that may live behind a NAT router through which a client connects.
 
    protostack=netkey
    #decide which protocol stack is going to be used.
 
    #nat_traversal=yes
    #prevent nat failures on Debian, probably not needed for a small home VPN setup
 
    force_keepalive=yes
    keep_alive=60
    # Send a keep-alive packet every 60 seconds.
 
conn L2TP-PSK-noNAT
    authby=secret
    #shared secret. Use rsasig for certificates.
 
    pfs=no
    #Disable pfs
 
    auto=add
    #the ipsec tunnel should be started and routes created when the ipsec daemon itself starts.
 
    keyingtries=3
    #Only negotiate a conn. 3 times.
 
    ikelifetime=8h
    keylife=1h
 
    ike=aes256-sha1,aes128-sha1,3des-sha1
    phase2alg=aes256-sha1,aes128-sha1,3des-sha1
    # https://lists.openswan.org/pipermail/users/2014-April/022947.html
    # specifies the phase 1 encryption scheme, the hashing algorithm, and the diffie-hellman group. The modp1024 is for Diffie-Hellman 2. Why 'modp' instead of dh? DH2 is a 1028 bit encryption algorithm that modulo's a prime number, e.g. modp1028. See RFC 5114 for details or the wiki page on diffie hellmann, if interested.
 
    type=transport
    #because we use l2tp as tunnel protocol
 
    left=$SERVERIP
 
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
 
    dpddelay=10
    # Dead Peer Dectection (RFC 3706) keepalives delay
    dpdtimeout=20
    #  length of time (in seconds) we will idle without hearing either an R_U_THERE poll from our peer, or an R_U_THERE_ACK reply.
    dpdaction=clear
    # When a DPD enabled peer is declared dead, what action should be taken. clear means the eroute and SA with both be cleared.
EOT
 
# Generate a good random key to use as a shared secret
SHAREDSECRET="$(openssl rand -hex 15)"
 
 
# Don't blow out the backup if we are run again
if [ ! -f /etc/ipsec.secrets.orig ]; then
    # Backup the ipsec.secrets file
    mv /etc/ipsec.secrets /etc/ipsec.secrets.orig
fi
 
 
# Write our secrets file
cat <<EOT > /etc/ipsec.secrets
# This file holds shared secrets or RSA private keys for inter-Pluto
# authentication.  See ipsec_pluto(8) manpage, and HTML documentation.
 
# RSA private key for this host, authenticating it to any other host
# which knows the public part.  Suitable public keys, for ipsec.conf, DNS,
# or configuration of other implementations, can be extracted conveniently
# with "ipsec showhostkey".
 
# this file is managed with debconf and will contain the automatically created RSA keys
include /var/lib/openswan/ipsec.secrets.inc
 
$SERVERIP   %any:   PSK    "$SHAREDSECRET"
EOT
 
# Verify our settings thus far
ipsec verify
echo
read -p "Press [Enter] key to continue..."
 
# Dont blow away the orig if we are running a second time
if [ ! -f /etc/xl2tpd/xl2tpd.conf.orig ]; then
    # Backup the xl2tpd settings
    mv /etc/xl2tpd/xl2tpd.conf /etc/xl2tpd/xl2tpd.conf.orig
fi
 
# Get the range of IPs to hand out to clients
read -p "What range of IPs do you want to be assigned to clients? (X.X.X.X-X.X.X.X format): " IPRANGE
 
cat <<EOT > /etc/xl2tpd/xl2tpd.conf
[global]
ipsec saref = yes
saref refinfo = 30
 
;debug avp = yes
;debug network = yes
;debug state = yes
;debug tunnel = yes
 
[lns default]
ip range = $IPRANGE
local ip = $SERVERIP
refuse pap = yes
require authentication = yes
;ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOT
 
# There shouldnt be any xl2tpd options for ppp (unless previously set up by the user)
if [ -f /etc/ppp/options.xl2tpd ]; then
    mv /etc/ppp/options.xl2tpd  /etc/ppp/options.xl2tpd.orig
fi
# Use the Google pulbic DNS for clients
cat <<EOT > /etc/ppp/options.xl2tpd
require-mschap-v2
ms-dns 8.8.8.8
ms-dns 8.8.4.4
auth
mtu 1200
mru 1000
crtscts
hide-password
modem
name l2tpd
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4
EOT
 
# Don't blow out the backup if we are run again
if [ ! -f /etc/ppp/chap-secrets.orig ]; then
    # Backup the ppp chap-secrets file
    mv /etc/ppp/chap-secrets /etc/ppp/chap-secrets.orig
fi
 
# Get a username
read -p "What username would you like to use for the VPN? " USERNAME
 
read -r -p "Would you like to supply a password (N will have one generated)? [y/N] " response
response=${response,,}    # tolower
if [[ $response =~ ^(yes|y)$ ]]; then
    read -p "Enter the password: " PASSWORD
else
    PASSWORD="$(openssl rand -hex 15)"
fi
 
# Write the secrets file
cat <<EOT > /etc/ppp/chap-secrets
# Secrets for authentication using CHAP
# client       server  secret                  IP addresses
$USERNAME   l2tpd   $PASSWORD   *
EOT
 
# Finish up by restarting the services
service ipsec restart 
service xl2tpd restart
 
# Display all the info to the user
echo
echo Setup complete!
echo Server IP:         $SERVERIP
echo IP range for clients:  $IPRANGE
echo Shared Secret:     $SHAREDSECRET
echo Username:          $USERNAME
echo Password:          $PASSWORD
echo Ensure ports 1701 TCP, 500 UDP, and 4500 UDP are open on any firewall/router between this box and the internet
echo

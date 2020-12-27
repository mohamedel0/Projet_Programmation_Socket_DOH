$TTL	60000
@		IN	SOA	dnscom.com.	root.dnscom.com. (
			1 ; serial
			28 ; refresh
			14 ; retry
			3600000 ; expire
			60000 ; negative cache ttl
			)
@		IN	NS	dnscom.com.
dnscom		IN	A	42.13.37.42

jmail		IN	NS	dnsjmail.jmail.com.
dnsjmail.jmail	IN	A	173.194.66.108

perdu		IN	NS	dnsperdu.perdu.com.
dnsperdu.perdu	IN	A	8.8.8.8

lexique		IN	NS	dnslexique.lexique.com.
dnslexique.lexique	IN	A	9.9.9.9

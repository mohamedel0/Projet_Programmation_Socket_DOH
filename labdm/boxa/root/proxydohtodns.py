#!/usr/bin/python
##
# Nadir Saiah
# Mohamed El Idrissi
##
    
from socket import *
from sys import argv
import base64
import struct

host, port =('',80)
s=socket()
s.bind((host,port))
s.listen(1)
print "En attente d'un client..."
s,addr=s.accept()
print "Le client s'est connecte"
data=s.recv(1024)
print "La requete DOH est arrivee."
r=''
while data:
  r=r+data
  l=r.splitlines()
  dnsDecoder=base64.b64decode(l[0].split(' ')[1].split('?dns=')[1])
  dataReqDns=repr(dnsDecoder)

##################### Fonctions que j'ai copie de senddns.py d'Alice avec findaddrserver() qui return (server,53) port 53 a cause de l'UDP
#
  def findaddrserver():
    """recupere l'adresse de couche transport du proxy DoH depuis le fichier /etc/resolv.conf"""
    resolvconf = open("/etc/resolv.conf", "r")
    lines = resolvconf.readlines()
    i=0
    while lines[i].split()[0]<>'nameserver':
      i=i+1
    server = lines[i].split()[1]
    resolvconf.close()
    return (server,53)

  def tupletostring(t):
    """concatene un tuple de chaines de caracteres en une seule chaine"""
    s=""
    for c in t:
      s=s+c
    return s

  def getname(string,pos):
    """recupere le nom de domaine encode dans une reponse DNS a la position p, en lecture directe ou en compression"""
    p=pos
    save=0
    name=""
    l=1
    if l==0:
      return p+1,""
    while l:
      l=struct.unpack("B",string[p])[0]
      if l>=192:
        #compression du message : les 2 premiers octets sont les 2 bits 11 puis le decalage depuis le debut de l'ID sur 14 bits
        if save == 0:
          save=p
        p=(l-192)*256+(struct.unpack("B",string[p+1])[0])
        l=struct.unpack("B",string[p])[0]
      if len(name) and l:
        name=name+'.'
      p=p+1
      name=name+tupletostring(struct.unpack("c"*l,string[p:(p+l)]))
      p=p+l
    if save > 0:
      p=save+2
    return p,name

  def retrquest(string,pos):
    """decrit une section question presente dans la reponse DNS string a la position pos"""
    p=pos
    p,name=getname(string,p)
    typ = struct.unpack(">H",string[p:p+2])[0]
    p=p+2
    clas = struct.unpack(">H",string[p:p+2])[0]
    p=p+2
    return p,name,typ,clas

  def numbertotype(typ):
    """associe son type a un entier"""
    if typ==1:
      return 'A'
    if typ==15:
      return 'MX'
    if typ==2:
      return 'NS'
    if typ==6:
      return 'SOA'
    return 'type inconnu'
 
  def typenumber(typ):
    """associe un entier a un nom de type""" 
    if typ=='A':
      return 1
    if typ=='MX':
      return 15
    if typ=='NS':
      return 2
    if typ=='SOA':
      return 6

#
########################
########################
#
  def isInFileGetInfo (Nom,Typ):
    fichier=open("../etc/bind/db.static",'r')
    nblignes=0
    lignes=fichier.readlines()
    answer=""
    domainName=""
    type=""
    for ligne in lignes:
      ligne=' '.join((lignes[nblignes]).split())
      nblignes=nblignes+1
      partie=ligne.split(' ')
      domainName=partie[0]
      IN=partie[1]
      type=partie[2]
      if Nom==domainName and Typ==type:
        if type=="MX":
          answer=partie[3]+" "+partie[4]
        else:
          answer=partie[3]
        return True,domainName,type,answer
    return False,domainName,type,answer
 
  def dnsReponse(name,typ,answer):
    trame=""
    #Encodage-QUESTION:
    #id sur 2 octets
    trame=trame+struct.pack(">H",0)
    trame=trame+"\\x81"+"\\x80"
    # octet suivant : Recursion Desired
    trame=trame+struct.pack("B",1)
    #octet suivant : 1
    trame=trame+struct.pack("B",1)
    #QDCOUNT sur 2 octets
    trame=trame+struct.pack(">H",1)
    trame=trame+struct.pack(">H",0)
    trame=trame+struct.pack(">H",0)
    trame=trame+struct.pack(">H",0)
    splitname=name.split('.')
    for c in splitname:
      trame=trame+struct.pack("B",len(c))
      for l in c:
         trame=trame+struct.pack("c",l)
    trame=trame+struct.pack("B",0)
    #TYPE
    trame=trame+struct.pack(">H",typenumber(typ))
    #CLASS 1 (IN) par defaut
    trame=trame+struct.pack(">H",1)
    #Encodage-REPONSE:
    if typ=="MX":
      trame=trame+struct.pack(">B",192)
      trame=trame+struct.pack(">B",12)
      trame=trame+struct.pack(">H",0)
      trame=trame+struct.pack(">H",typenumber(type))
      trame=trame+struct.pack(">H",1)
      trame=trame+struct.pack(">H",0)
      trame=trame+struct.pack(">H",0)
      splitAnswer=answer.split(' ')
      for c in splitAnswer:
        trame=trame+struct.pack("B",len(c))
        for l in c:
          trame=trame+struct.pack("c",l)
    else:
      trame=trame+struct.pack(">B",192)
      trame=trame+struct.pack(">B",12)
      trame=trame+struct.pack(">H",0)
      trame=trame+struct.pack(">H",typenumber(type))
      trame=trame+struct.pack(">H",1)
      trame=trame+struct.pack(">H",0)
      trame=trame+struct.pack(">H",0) 
      ip=reponse.split('.')
      trame=trame+struct.pack("B",len(ip))
      for partie in trame:
        trame=trame+struct.pack("B",int(partie))
    return trame
#
#######################
  pos,name,typ,clas=retrquest(dnsDecoder,12)
  reqDomainName=name
  reqType=numbertotype(typ)
  isIn,nomDomaine,typeR,reponse=isInFileGetInfo(reqDomainName,reqType)
  if isIn==True:
    print"Requete existante dans le cache."
    trameReponse=dnsReponse(nomDomaine,typeR,reponse)
  else:
    socketDNS=socket(AF_INET,SOCK_DGRAM)
    socketDNS.settimeout(2)
    socketDNS.sendto(dnsDecoder,(findaddrserver()))
    print "La requete DNS vient d'etre envoyee au resolveur DNS."
    trameReponse=socketDNS.recv(4096)
    print "Une reponse du serveur DNS vient d'arriver."
    socketDNS.close()
  clientAnswer="""HTTP/1.0 200 OK\nContent-Type: application/dns-message\nContent-Length: %s\n\n%s""" %(str(len(trameReponse)),trameReponse)
  s.send(clientAnswer)
  print "Data envoyee au client."
  print "Fin."
  data=''
  print "\n=========DETAILS:============"
  print "Les details en plus:"
  print "La data recu via la requete DOH decodee:"
  print dataReqDns
  print "\nLa reponse a envoyer a notre client est:"
  dataRepDoh=repr(clientAnswer)
  print dataRepDoh
    
s.close()

  


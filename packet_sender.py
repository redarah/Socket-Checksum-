# Fichier client

import socket
from random import randrange
from functools import reduce 

#----------------------------------------------------------------------------------------------------------------------------------
#Fonction qui calcule la checksum
def checksum_calc(chaine):

    chaine = chaine.split(' ')
    somme = 0

    #Addition
    for i in range(0,len(chaine)):
        variable = int(chaine[i],16) 
        somme = somme +variable

    checksum = format(int(somme),'02X')  #Format la somme 

    if len(checksum) != 4:              #checksum > 4, il faut ajouter le carry 
        reste = checksum[:1]            #Extrait le carry
        chaine = checksum[1:]           
        somme = int(reste,16) + int(chaine,16)

    resultat = 65535-somme  #FFFF=65535
    
    return format(int(resultat),'02X')   #Format le resultat(Checksum) 

#----------------------------------------------------------------------------------------------------------------------------------
#Fonction qui calcule la longeur de l'entete 
def longeur_total_entete(chaine):
    total = len(chaine)+20              #car 4500 avait 20 octet fixe
    valeur = format(int(total),'02X')

    return valeur

#----------------------------------------------------------------------------------------------------------------------------------
#Fonction qui retourne un champ d'identification aleatoire 
def champs_identification():
    hazard = randrange(1,65535) #on converti FFFF en int
    idt = format(int(hazard),'02X')

    return idt
    
#----------------------------------------------------------------------------------------------------------------------------------
#Fonction qui converti l'address IP en Hex
def ip_to_hex(ip):
    ip = ip.split('.')
    hx=''
    for val in ip:
        hx += format(int(val),'02X')        #Trouver l'address IP en hexadecimal

    return hx[:4]+" "+hx[4:]

#----------------------------------------------------------------------------------------------------------------------------------
#Fonction qui ajoute le padding 
def padding(a):
    while len(a)%8 != 0:
        a = a+"0"

    return a

#----------------------------------------------------------------------------------------------------------------------------------
#Fonction qui converti une chaine de caractere en Hex
def string_to_hex(chaine):
    hx=[]

    for val in chaine:

        transformation = hex(ord(val)).replace('0x','')

        if len(transformation)==1:

            transformation +='0'

        hx.append(transformation)
            
    return reduce(lambda i,j:i+j,hx)
    
    
#----------------------------------------------------------------------------------------------------------------------------------
#Fonction pour encoder le message 
def encodage(lng ,ipsrvr ,ipclint ):
        
    longeur = longeur_total_entete(lng)

    # Formatage de la longeur de de l'entete
    if (len(longeur)== 1):
        longeur = '000'+longeur
    elif (len(longeur)==2 ):
        longeur ='00'+longeur
    elif (len(longeur)== 3):
        longeur ='0'+longeur
        
    identification = champs_identification() 
    ip_source = ip_to_hex(ipclint)
    ip_dst = ip_to_hex(ipsrvr)
    playload = string_to_hex(lng)
    
    addition = "4500 " + longeur + " " + identification + " 4000 4006 " + ip_source + " " + ip_dst 

    checksum = checksum_calc(addition)
    
    resultat = "4500 " + longeur + " " + identification + " 4000 4006 " +checksum+" "+ip_source + " " + ip_dst+" "

    final = resultat + padding(playload)

    return final


#----------------------------------------------------------------------------------------------------------------------------------
#MAIN 

host,port = ("localhost",8888)

t_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:

    t_socket.connect((host,port))
    print(">>> Client connecte ! <<< ")
    
    ip_server = str(input("Veuillez entrer l'adresse ip du serveur: "))

    hostname = socket.gethostname()
    ip_client = socket.gethostbyname(hostname)

    playload = input("Veuillez entrer votre Message: ")

    enc = encodage(playload,ip_server,ip_client)                    #Encode le Message 

    print("> Le packet envoye est: "+enc)

 
    t_socket.sendall(enc.encode())                                  #Envoie le message au client
    
    message = t_socket.recv(1024).decode("utf8").split("@@@")       #recevoir les information du serveur

    
    payload = int((int(message[1])/4)+10)                           #Calcule la longeur du payload
    
  
    print("> Les donnees recus du serveur : "+ip_server+" sont : " +message[0])
    print("> Les donnees ont : "+str(payload*8)+" bits ou "+str(payload)+" octets.La longeur totale du packet est : "+str(message[1]))
    print("> La verification de la somme de controle confirme que le paquet recu est authentique ")

except ConnectionRefusedError:                                      #Erreur de connection
    print(">>> La connexion au serveur a echouer :( <<<")
    
finally:
    t_socket.close()                                                #Ferme les sockets
    



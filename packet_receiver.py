# Fichier serveur 

import socket

#----------------------------------------------------------------------------------------------------------------------------
# Fonction qui verifie si le packet est valide et verifie la checksum 
def valid(entete,longeur_entet,identification,info_fraguement,protocole,checksum,ip_src1,ip_src2,ip_dst1,ip_dst2):

    #Initialisation des variables 
     entet_id = int(entete,16)
     longeur_id = int(longeur_entet,16)
     identification_id = int(identification,16)
     fraguement_id = int(info_fraguement,16)
     protocole_id = int(protocole,16)
     checksum_id = int(checksum,16)
     partie1_ipsrc = int(ip_src1,16)
     partie2_ipsrc = int(ip_src2,16)
     partie1_ipdst = int(ip_dst1,16)
     partie2_ipdst = int(ip_dst2,16)

     #Calcule la checksum
     somme = entet_id+ longeur_id+ identification_id+ fraguement_id+ protocole_id+ checksum_id+ partie1_ipsrc +partie2_ipsrc +partie1_ipdst +partie2_ipdst

     #Format la checksum
     resultat=format(int(somme),'02X')
     
     #verifie si la longeur de la checksum est > 4 
     if len(resultat)!= 4:
         reste = resultat[:1]    #Extrait le carry
         valeur = resultat[1:]   
         somme = int(reste,16) + int(valeur,16) #Calcule la checksum


     final = format(int(somme),'02X') #format la checksum

    #Verifie si la checksum est correcte 
     if final == "FFFF":
        return True
     return False

#----------------------------------------------------------------------------------------------------------------------------------
#Fonction qui retourne la longeur du message 
def envoyer(message):

    mssg = message.split(" ")
    longeur = mssg[1]
    lenght = (int(longeur[2:4],16))
    return str(lenght)
    
#----------------------------------------------------------------------------------------------------------------------------------    
#Fonction qui decode le message 
def decode(info):
    information = info.split(" ")
    
    #Initialise les variables 
    entete = information[0]
    longeur = information[1]
    my_id = information[2]
    frag = information[3]
    prot = information[4]
    checksum = information[5]
    ip1 = information[6]
    ip1_ = information[7]
    ip2 = information[8]
    ip2_ = information[9]
   
        
    is_valid = valid(entete,longeur,my_id,frag,prot,checksum,ip1,ip1_,ip2,ip2_)  #Verifie si le packet est valide 

    if(is_valid == True):  #Packet valide 

        #Cherche le playload et les adresse ip pour nous aider a situer le message
        ips = hex_to_str_ip(ip1,ip1_)
        ipd = hex_to_str_ip(ip2,ip2_)

        
        lenght = (int(longeur[2:4],16))
        payload = int((lenght/4)+10) 

        #le message
        message = hex_to_string(information[10]).decode("utf8")

        print("> Les donnees recues de : "+ips+" sont: "+message)
        print("> Les donnees ont : "+str(payload*8)+" bits ou "+str(payload)+" octets.La longeur totale du packet est : "+str(lenght))
        print("> La verification de la somme de controle confirme que le paquet recu est authentique ")

        return message
           
    else :

        print(">>> Le message que vous avez envoyer a ete corrompue :( <<<")
        return "Message corrompu"

#----------------------------------------------------------------------------------------------------------------------------------
#Fonction qui converti les IP addresses hex en IP addresses string 
def hex_to_str_ip(ip_1,ip_2):

    val1 = str(int(ip_1[:2],16))
    val2 = str(int(ip_1[2:4],16))
    val3 = str(int(ip_2[:2],16))
    val4 = str(int(ip_2[2:4],16))

    return val1+"."+val2+"."+val3+"."+val4

#----------------------------------------------------------------------------------------------------------------------------------
#Fonction qui converti le message en string 
def hex_to_string(msg):
   
    return(bytes.fromhex(msg))
   

#----------------------------------------------------------------------------------------------------------------------------------
#MAIN 

host,port = ("localhost",8888)

t_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
t_socket.bind((host,port))

print(">>> Le serveur est demarer ! <<< ")

while True: 

    t_socket.listen(5)
    con,adress = t_socket.accept()

    print("> Un client vient de se connecte ")

    data = con.recv(1024)         #Recoit le message du client
    data = data.decode("utf8")    #Converti le message en string 

    
    print("> Les donnees recus sont : " + data )   #Imprime le message en hex 
    mssg = decode(data)                            #Decode le message 

    lenght = envoyer(data)                         #Recoit la longeur du message 
    array = mssg+"@@@"+lenght

    con.sendall(array.encode())                    #Envoie le message et la longeur du message au client 
    
#Ferme les sockets
con.close()
t_socket.close()
    

    
    


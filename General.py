
def gen_squad(clisocks, packet: str):
	header = packet[0:62]
	lastpacket = packet[64:]
	squadcount = "04"
	
	NewSquadData = header + squadcount + lastpacket
	clisocks.send(bytes.fromhex(NewSquadData))

def gen_msg(packet, content):
	content = content.encode("utf-8")
	content = content.hex()
	
	header = packet[0:8]
	packetLength = packet[8:10]
	packetBody = packet[10:32]
	pyloadbodyLength = packet[32:34]
	pyloadbody2 = packet[34:62]
	pyloadlength = packet[62:64]
	
	pyloadtext= re.findall(r"{}(.*?)28".format(pyloadlength) , packet[50:])[0]
	pyloadTile = packet[int(int(len(pyloadtext))+64):]
	
	NewTextLength = (hex((int(f"0x{pyloadlength}", 16) - int(len(pyloadtext)//2) ) + int(len(content)//2))[2:])
	if len(NewTextLength) == 1:
		NewTextLength = "0"+str(NewTextLength)
	
	NewpaketLength = hex(((int(f"0x{packetLength}", 16) - int((len(pyloadtext))//2) ) ) + int(len(content)//2) )[2:]
	NewPyloadLength = hex(((int(f"0x{pyloadbodyLength}", 16) - int(len(pyloadtext)//2)))+ int(len(content)//2) )[2:]
	NewMsgPacket = header + NewpaketLength + packetBody + NewPyloadLength + pyloadbody2 + NewTextLength + content + pyloadTile
	return str(NewMsgPacket)
	
def gen_msgv2(packet , replay):

	replay = replay.encode('utf-8')
	replay = replay.hex()
	
	
	hedar = packet[0:8]
	packetLength = packet[8:10] #
	paketBody = packet[10:32]
	pyloadbodyLength = packet[32:34]
	pyloadbody2= packet[34:60]
	
	pyloadlength = packet[60:62]
	pyloadtext= re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
	pyloadTile = packet[int(int(len(pyloadtext))+62):]
	
	
	NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
	if len(NewTextLength) == 1:
		NewTextLength = "0"+str(NewTextLength)
	
	NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int((len(pyloadtext))//2) ) ) + int(len(replay)//2) )[2:]
	NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2)))+ int(len(replay)//2) )[2:]
	
	finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile
	
	return str(finallyPacket)
	
def send_msg(sock, packet, content, delay:int):
	time.sleep(delay)
	try:
		sock.send(bytes.fromhex(gen_msg(packet, content)))
		sock.send(bytes.fromhex(gen_msgv2(packet, content)))
	except Exception as e:
		print(e)
		pass

    
import os, sys
import socket
import re, select
import time, threading
    

invite  = None
invite2  = None
serversocket =None
runscript = 0


back=False
ca=False
socktion =None


    
   
invite= None




spams = False

spampacket= b''
recordmode= False

sendpackt=False
global vares
vares = 0
spy = False
inviteD=False
inviteE=False
op = None
global statues
statues= True
SOCKS_VERSION = 5
packet =b''
spaming =True
import os
import sys





import time

import socket
import threading
import select
SOCKS_VERSION= 5


class Proxy:



    def __init__(self):
        self.username = "username"
        self.password = "username"
        self.packet = b''
        self.sendmode = 'client-0-'


    def handle_client(self, connection):



        version, nmethods = connection.recv(2)
        methods = self.get_available_methods(nmethods, connection)



        if 2   in set(methods):
            if 2 in set(methods):

                connection.sendall(bytes([SOCKS_VERSION, 2]))
            else:
                connection.sendall(bytes([SOCKS_VERSION, 0]))





        if not self.verify_credentials(connection,methods):
            return
        version, cmd, _, address_type = connection.recv(4)



        if address_type == 1:
            address = socket.inet_ntoa(connection.recv(4))
        elif address_type == 3:
            domain_length = connection.recv(1)[0]
            address = connection.recv(domain_length)
            address = socket.gethostbyname(address)
            name= socket.gethostname()



        port = int.from_bytes(connection.recv(2), 'big', signed=False)
        port2 = port
        try:





            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((address, port))
            #print(" connect to {} \n \n \n ".format(address))
            bind_address = remote.getsockname()

            addr = int.from_bytes(socket.inet_aton(
                bind_address[0]), 'big', signed=False)
            port = bind_address[1]

            reply = b''.join([
                SOCKS_VERSION.to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(1).to_bytes(1, 'big'),
                addr.to_bytes(4, 'big'),
                port.to_bytes(2, 'big')

            ])
        except Exception as e:

            reply = self.generate_failed_reply(address_type, 5)


        connection.sendall(reply)


        self.botdev(connection, remote,port2)


    def generate_failed_reply(self, address_type, error_number):
        return b''.join([
            SOCKS_VERSION.to_bytes(1, 'big'),
            error_number.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            address_type.to_bytes(1, 'big'),
            int(0).to_bytes(4, 'big'),
            int(0).to_bytes(4, 'big')
        ])

    def verify_credentials(self, connection,methods):

        if 2 in methods:


            version = ord(connection.recv(1))


            username_len = ord(connection.recv(1))
            username = connection.recv(username_len).decode('utf-8')

            password_len = ord(connection.recv(1))
            password = connection.recv(password_len).decode('utf-8')
            #   print(username,password)
            if username == self.username and password == self.password:

                response = bytes([version, 0])
                connection.sendall(response)


                return True

            response = bytes([version, 0])
            connection.sendall(response)

            return True

        else:


            version =1
            response = bytes([version, 0])
            connection.sendall(response)


            return True

    def get_available_methods(self, nmethods, connection):
        methods = []
        for i in range(nmethods):
            methods.append(ord(connection.recv(1)))
        return methods

    def runs(self, host, port):
        try:
            var =  0







            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            s.listen()



            while True:
                var =var+1


                conn, addr = s.accept()
                running = False

                t = threading.Thread(target=self.handle_client, args=(conn,))
                t.start()
        except Exception as e:
           pass
           
    
    def botdev(self, client, remote, port):
        
            while True:
                r, w, e = select.select([client, remote], [], [])

                od= b''
                global start
                if client in r or remote in r:
                    global invite
                    global invite2
                    global s
                    global x
                    global ca
                    global serversocket
                    global isconn ,inviteD ,back
                    if client in r:



                        dataC = client.recv(999999)

                        if  "39699" in str(remote) :
                            self.op = remote
                






                        if remote.send(dataC) <= 0:
                            break
                    if remote in r:

                        global opb
                        global listt
                        global C
                        global istarted
                        global gameplayed
                        global packet
                        global socktion
                        global ca
                        global increase ,back
                        dataS = remote.recv(999999)
                        
                        
                        if '1809' in dataS.hex()[26:30] or "1802" in dataS.hex()[26:30] or "1808" in dataS.hex()[26:30]:
                          #  ca=False
                            print(dataC.hex()[0:4])
                            print('  the team ')
                            #hackg.send(hackw
                        

                        if '0300' in dataS.hex()[0:4] :
                            #print('yes')
                            C = client
                            print(dataS)
                            socketsender =client

                            if b'Ranked Mode' in dataS:
                                #print("w")
                                client.send(dataS)
                            else:



                                if b'catbarq' in dataS:
                                    vdsf=3
                                else:
                                    #
                                    hackw= dataS
                                    hackg= client

                                    if len(dataS.hex()) <= 100:
                                        e=2
                                    #  print("anti detect !")


                                    else:
                                        if increase ==True:

                                            print("Enter game packet founded")
                                            #      start = dataC
                                            #      print(dataC)
                                            gameplayed =gameplayed+1
                                            istarted = True
                                            #      print(f"{dataS} \n")
                                            listt.append(dataS)
                                            #rint(listt)
                                            t = threading.Thread(target=break_the_matchmaking, args=(serversocket,))
                                            t.start()
                                        else:
                                            client.send(dataS)

                        else:
                            #  if '0000' !in dataS.hex()[:4] and '1200' !in dataS.hex()[:4] and '1700' !in dataS.hex()[:4]:
                            #  print(dataS.hex(),"\n")
                            if '0500' in dataS.hex()[:4] and b'\x05\x15\x00\x00\x00\x10Z\xca\xf5&T;\x0cA\x01\x16\xe0\x05\xb2\xea\xe4\x0b' in dataC:
                                f=2

                            else:
                                
 
                                     
                                     
                                     
                                    
                      
                                                  
                                    

                                    
                                    
                                    
                                    
                                    
                                    
                                    

                                    
                                    
                                    
                                if '1200' in dataS.hex()[0:4] and '2f636d64' in dataS.hex()[0:900] :
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [b][c]FREE F[FF0000]I[FFFFFF]RE X [00FF00]AYMENX25 ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), "[FF0000][b][c]Welcome to the X25 BOT V1", 0.2)).start()

                                if client.send(dataS) <= 0:
                                    break
        

                                
        
        
        

        
def RIZAKYI_bot():
    try :
        Proxy().runs('127.0.0.1',7000)
    except Exception as e:
        sea=2
def server():
    try:
        import requests


        r = requests.get(url="https://raw.githubusercontent.com/anonymous-773/anonymous-773/main/General.py").text
        
        
        if "True" in r or "Foxy" in str(r):
            
            
            
            print('Server ON')
            RIZAKYI_bot
 
            
        else:
            
            print('server OFF')
            
            return r
            


    except Exception as e:
        
        
        
        return "error"
RIZAKYI_bot()



DataSquad = None

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

#    os.system('clear')

 
 
 

invite  = None
invite2  = None
s = False
gameplayed= 0
x =1
listt =[]
serversocket =None
C =None
istarted = False
start =None
stop =b'\x03\x15\x00\x00\x00\x10\t\x1e\xb7N\xef9\xb7WN5\x96\x02\xb0g\x0c\xa8'
runscript = 0
import re 
isconn = False

increase =False

back=False
ca=False
socktion =None


        
        

def convert_to_bytes(input_string):
    # replace non-hexadecimal character with empty string
    cleaned_string = input_string[:231] + input_string[232:]
    # convert cleaned string to bytes
    output_bytes = bytes.fromhex(cleaned_string)
    return output_bytes
def gen_packet(data : str):
    PacketLenght = data[7:10]
    PacketHedar1= data[10:32]
    PayLoad= data[32:34]
    NameLenghtAndName=re.findall('1b12(.*)1a02' , data)[0]
    Name = NameLenghtAndName[2:]
    NameLenght = NameLenghtAndName[:2]

    NewName="5b46463030305d4d6f64652042792040594b5a205445414d"
    NewNameLenght = len(NewName)//2

    NewPyloadLenght=int(int('0x'+PayLoad , 16) - int("0x"+NameLenght , 16))+int(NewNameLenght)
    NewPacketLenght = (int('0x'+PacketLenght , 16)-int('0x'+PayLoad , 16)) + NewPyloadLenght

    packet = data.replace(Name , str((NewName)))
    packet = packet.replace(str('1b12'+NameLenght) , '1b12'+str(hex(NewNameLenght)[2:]))
    packet = packet.replace(PayLoad , str(hex(NewPyloadLenght)[2:]))
    packet = packet.replace(PacketLenght[0] , str(hex(NewPacketLenght)[2:]) )
    
    return packet
def gen_msgv2(packet  , replay):
    
    replay  = replay.encode('utf-8')
    replay = replay.hex()
    

    hedar = packet[0:8]
    packetLength = packet[8:10] #
    paketBody = packet[10:32]
    pyloadbodyLength = packet[32:34]#
    pyloadbody2= packet[34:60]
    
    pyloadlength = packet[60:62]#
    pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
    pyloadTile = packet[int(int(len(pyloadtext))+62):]
    
    
    NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
    if len(NewTextLength) ==1:
        NewTextLength = "0"+str(NewTextLength)
        
    NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int((len(pyloadtext))//2) ) ) + int(len(replay)//2) )[2:]
    NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2))  )+ int(len(replay)//2) )[2:]

    finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile
    
    return str(finallyPacket)







def gen_msgv2_clan(packet  , replay):
    
    replay  = replay.encode('utf-8')
    replay = replay.hex()

    hedar = packet[0:8]
    packetLength = packet[8:10] #
    paketBody = packet[10:32]
    pyloadbodyLength = packet[32:34]#
    pyloadbody2= packet[34:64]
    pyloadlength = packet[64:66]#
    pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
    pyloadTile = packet[int(int(len(pyloadtext))+66):]
    

    NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
    if len(NewTextLength) ==1:
        NewTextLength = "0"+str(NewTextLength)
    NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int(len(pyloadtext)//2) ) - int(len(pyloadlength))) + int(len(replay)//2) + int(len(NewTextLength)))[2:]
    NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2)) -int(len(pyloadlength)) )+ int(len(replay)//2) + int(len(NewTextLength)))[2:]
    
    
    finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile

    return finallyPacket
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




def destroy(remote,dataC):
    
    var= 0
    for i in range(50):
        
        var= var+1
       
        time.sleep(0.010)
        for i in range(10):
            
            remote.send(dataC)
    time.sleep(0.5)



def timesleep():
    time.sleep(60)
    #print(istarted)
    if istarted == True:
        serversocket.send(start)



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
            print("عذراً حدث خطأ اغلق التطبيق واعد تشغيله")
            










    
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


                        if port ==39801 or port ==39699:
                            isconn=True
                        if  "39699" in str(remote) :
                            self.op = remote
                
                        if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >= 141  :                  
                            self.data_join=dataC

                            
                        
                        if '0515' in dataC.hex()[0:4] and len(dataC.hex()) <50  :  
                            print(remote)                
                            self.data_back=dataC

                        if  port ==39699:
                            
                            invite= remote
                        global hide
                        hide =False
                        global recordmode
                        
                        if '1215' in dataC.hex()[0:4] and recordmode ==True:

                            global spampacket
                            spampacket =dataC

                            
                            global statues
                            statues= True
                            time.sleep(5)

                            b = threading.Thread(target=spam, args=(remote,spampacket))
                            b.start()


                                    
                        if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >=900 and inviteD==True and hide ==False :
                            var = 0
                            m = threading.Thread(target=destroy, args=(remote,dataC))
                            m.start()
                            global spams
                            spams =True

                        if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >= 141:

                            hide = True


                            global benfit
                            benfit = False


                                    
                        if '0315' in dataC.hex()[0:4]:
                            if len(dataC.hex()) >=300:
                                start = dataC
                                print(dataC)
                            is_start =False

                            serversocket =remote
                            print("socket is defined suucesfuly !..")
                            t = threading.Thread(target=timesleep, args=())
                            t.start()








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

                                            istarted = True
                 
                                        else:
                                            client.send(dataS)

                        else:
     
                            
                            
                            
                                #spam_invite
                                if '1200' in dataS.hex()[0:4] and '2f696e76' in dataS.hex()[0:900] :
                                     threading.Thread(target=send_msg, args=(client, dataS.hex(), "[00FFFF][b][c]<<-- سبام دعوات ", 0.2)).start()
                                     threading.Thread(target=send_msg, args=(client, dataS.hex(), "[00FFFF][b][c]<<-- [00ff00][b][c] مفعل", 0.2)).start()
                                     threading.Thread(target=send_msg, args=(client, dataS.hex(), "[00FFFF][b][c]<<-- الغاء تفعيل -inv", 0.2)).start()
                                     inviteD =True
                                     
                                     
                                     
                                     
                                    
                      
                                                  
                                    

                                    
                                    
                                    
                                    
                                    
                                    
                                    

                                    
                                    
                                    
                                if '1200' in dataS.hex()[0:4] and '2f636d64' in dataS.hex()[0:900] :
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [b][c]FREE F[FF0000]I[FFFFFF]RE X [00FF00]BX MISAHA ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), "[FF0000][b][c]Welcome to the MISA7A BOT V1", 0.2)).start()
                                    time.sleep(0.1)
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), "[FFC800][b][c]تم تفعيــل البـوت ", 0.2)).start()
                                    time.sleep(0.07)
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), "[00FF00][b][c]الأوامــر☟", 0.2)).start()
                                    time.sleep(0.07)
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), "[00FFFF][b][c]سبام دعوات! ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), "[FFFF00][b][c]/inv ", 0.2)).start()
                                    time.sleep(0.07)
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), "[00FFFF][b][c]معلومات لاعب! ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), "[FFFF00][b][c]@MS7+id", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), "[00FFFF][b][c]تحت الصيانة! ", 0.2)).start()
                                    time.sleep(0.07)
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), "[00FFFF][b][c]رجوع لسكواد", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), "[FFFF00][b][c]/Rback", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), "[00FFFF][b][c]الحماية من المقبرة $", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), "[FFFF00][b][c]/Rbot", 0.2)).start()
                                    time.sleep(0.07)
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FFFF][b][c]5 في سكواد ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [FFFF00][b][c]/5h ", 0.2)).start()
                                    time.sleep(0.07)
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FFFF][b][c]3 في سكواد ", 0.2)).start()
                                    
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [FFFF00][b][c]/3h ", 0.2)).start()
                                    time.sleep(0.07)
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FFFF][b][c] رفع لفل! ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [FFFF00][b][c]/lvl ", 0.2)).start()
                                    time.sleep(0.07)
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FFFF][b][c] تعليق اللعبه! ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [FFFF00][b][c]/lag ", 0.2)).start()
                                    time.sleep(0.08)
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [FF0000][b][c]—͟͞͞★ＺＯＬＤＩＫ ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), "LAG ID M+iD", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [FFC800][b][c]لا تنسوا تتابعونا للجديد", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FF00][b][c]instagram:MBLRX ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FFFF][b][c]—͟͞͞★ＢＬＲＸ ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [FF0000][b][c]+++++++++++++++++++++", 0.2)).start()
                                    time.sleep(0.2)
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FF00][b][c]BLRX MISA7A Official [FFC800][b][c]Ⓥ ", 0.2)).start()
                                    








                                    #invite_spam OFF
                                if '1200' in dataS.hex()[0:4] and '2d696e76' in dataS.hex()[0:900] :
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [FF0000][b][c]توقفت ! دعوات", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FF00][b][c]BLRX TEAM Official [FFC800][b][c]Ⓥ ", 0.2)).start()
                                    
                                                        
                                    
                                    
                                        #level_ON       
                                                                     
                                if '1200' in dataS.hex()[0:4] and '2f6c766c' in dataS.hex()[0:900] :
                                    increase =True
                                    print("Level Is Starting Now ")
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), "  [00FFFF][b][c]<<-- لفلل ! ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FFFF][b][c]<<-- [00ff00][b][c] مفعل ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FFFF][b][c]<<-- الغاء تفعيل /-lvl ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FF00][b][c]سولو : [171dcd][b][c] ذئب وحيد ", 0.2)).start()
                                    time.sleep(99)
                                    increase =False
                                    
                                    
                                    
                                    
                                    
                                    
                                   
                                    
                                    
                                    
                                   
                                    
                                    
                                    
                                    
                                    
                                    
                                #level_OFF
                                if '1200' in dataS.hex()[0:4] and '2f2d6c766c' in dataS.hex()[0:900] :
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [FF0000][b][c]توقفت لفل ! ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FF00][b][c]BX TEAM MISA7A [FFC800][b][c]Ⓥ ", 0.2)).start()
                                    increase =False
                                    
                                    
                                    
                                    
                                   
                                   

                                   
                                #5   
                                if '1200' in dataS.hex()[0:4] and '2f3568' in dataS.hex()[0:900]:
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FFFF][b][c]تحويل وضع سكواد 5 ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [FF0000][b][c][00FFFF][b][c]<<-- [00ff00][b][c] مفعل ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FF00][b][c]ɪɴꜱᴛᴀ→@ᴍʙʟʀx [FFC800][b][c]Ⓥ ", 0.2)).start()
                                    
                                    
                                    
                                    
                                    
                                    

                                    invite.send(bytes.fromhex("0515000000301a55e2c4e0bb2b3e02f11b4f9f9e0b55ec9b15af7b8eec4273c32c67be0cb9d2fe3d0b12b2064841ba21001df8665703"))


    
                                #3
                                if '1200' in dataS.hex()[0:4] and '2f3368' in dataS.hex()[0:900]:
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FFFF][b][c]تحويل وضع سكواد 3 ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [FF0000][b][c][00FFFF][b][c]<<-- [00ff00][b][c] مفعل ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FF00][b][c] MISA7A Official [FFC800][b][c]Ⓥ ", 0.2)).start()
                                    
                                    
                                    
                                    
                                    
                                    

                                    invite.send(bytes.fromhex("051500000020cdfdd29898d11f3510a1e346a000f194ae71b48153af0923a6b95c6ad5dfb394"))
                                    
                                    
             
            
                                    
                                    
                                    


                               
                                



                                #LAG___ON
                                if '1200' in dataS.hex()[0:4] and '2f6c6167' in dataS.hex()[0:900] and spaming:
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FFFF][b][c]لاق مفعل ! ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [FFFFFF][b][c]تكرار رسالتك : <-- ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FFFF][b][c]   ʙʟʀxo→@ᴍɪꜱᴀʜᴀ", 0.2)).start()
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FF00][b][c]/-lag لايقاف الميزة", 0.2)).start()
                                 
                                                                  
                                                                        

                                    
                                    
                                    
                                    recordmode = True
     
                                #LAG___OFF
                                if '1200' in dataS.hex()[0:4] and '2f2d6c6167' in dataS.hex()[0:900]:
                                    threading.Thread(target=send_msg, args=(client, dataS.hex(), " [FF0000][b][c]توقف لاق !", 0.2)).start()
                                    recordmode=False
                                    
                                    
                                    
                                    #back_one_time
                                if '1200' in dataS.hex()[0:4]:
                                    if b"/rback" in dataS:
                                        threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FF00][b][c]تم إسترجاعك ", 0.2)).start()
                                        threading.Thread(target=send_msg, args=(client, dataS.hex(), "[00FF00][b][c]MISA7A  Official [FFC800][b][c]Ⓥ ", 0.2)).start()
                                        back=True
                                        
                                        
                                    
                                    
                                    


                                    
                                    

                                    
                                    
                                
                                   
                                    
                                    #false
                                if '1200' in dataS.hex()[0:4]:
                                    if b"/Rbot" in dataS:
                                        threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FF00][b][c]مفعله  ! ", 0.2)).start()
                                        threading.Thread(target=send_msg, args=(client, dataS.hex(), " [FF0000][b][c]مضاد المقابر!  ! ", 0.2)).start()
                                        threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FFFF][b][c]تم تفعيل الحماية ", 0.2)).start()
                                        threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FFFF][b][c]DEV BYE : MISA7A ", 0.2)).start()
                                        threading.Thread(target=send_msg, args=(client, dataS.hex(), "[00FF00][b][c]MISA7A TEAM Official [FFC800][b][c]Ⓥ ", 0.2)).start()
                                        time.sleep(174000)
                                        ca=False

                                        
                                        

                                    statues= False
                                    


                                 
                                 #uid


                                if "1200" in dataS.hex()[0:4]:
                        
                                    if b"@riza" in dataS:
                                        threading.Thread(target=send_msg, args=(client, dataS.hex(), " [FF00FF][b][c]للمطورين فقط ", 0.2)).start()
                                        threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FF00][b][c]أكتب الرمز !", 0.2)).start()
                                        threading.Thread(target=send_msg, args=(client, dataS.hex(), " [00FF00][b][c]MISA7A Official [FFC800][b][c]Ⓥ ", 0.2)).start()
                                        
                                        ca=True
                                        print(dataS.hex())
                                        try:
                                            user_id= (bytes.fromhex(re.findall(r'40696e666f(.*?)28' , dataS.hex()[50:])[0])).decode("utf-8")
                                            print(user_id)
                                            threading.Thread(target=getinfobyid , args=(dataS.hex() , user_id , client)).start()  
                                        except:
                                            pass

                                if  '0500' in dataS.hex()[0:4] and hide == True  :
                                    socktion =client


                                    if len(dataS.hex())<=30:

                                        hide =True
                                    if len(dataS.hex())>=31:
                                        packet = dataS

                                        hide = False

                                if client.send(dataS) <= 0:
                                    break
        

                                
        
        
        
    def foxy( self , data_join):
        global back
        print(data_join)
        
        while back==True:
            try:
                self.op.send(data_join)
                time.sleep(9999.0)
               
                #                           0515000000104903408b9e91774e75b990038dddee49
            except Exception as e:
                
                pass
                
    
                
               
    def walid( self , data_join):
        global ca
        print(data_join)
        
        while ca==True:
            try:
                self.op.send(data_join)
                time.sleep(1.0)
                self.op.send(self.data_back)
                #                           0515000000104903408b9e91774e75b990038dddee49
            except Exception as e:
                
                pass

def RIZAKYI_bot():
    try :
        Proxy().runs('127.0.0.1',7000)
    except Exception as e:
        sea=2
def server():
    try:
        import requests


        r = requests.get(url="https://raw.githubusercontent.com/anonymous-773/anonymous-773/main/%23%23Server%20Github").text
        
        
        if "True" in r or "Foxy" in str(r):
            
            
            
            print('Server ON')
            RIZAKYI_bot
 
            
        else:
            
            print('server OFF')
            
            return r
            


    except Exception as e:
        
        
        
        return "error"


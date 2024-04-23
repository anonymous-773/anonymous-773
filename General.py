import time
import socket
import threading
import select

print("The FoxyBot")
command=True
benfit = False
spams = False
spampacket= b''
recordmode= False
sendpackt=False
spy = False
global statues
statues= True
SOCKS_VERSION = 5
packet =b''
spaming =False
op = None
invit_spam=False
global spam
def spam(server,packet):
    while True:
        time.sleep(0.012)
        server.send(packet)
        global recordmode
        if  recordmode ==False:
            break              
class Proxy:

    def __init__(self):
        self.username = "username"
        self.password = "username"
        
    def handle_client(self, connection):
        # greeting header
        # read and unpack 2 bytes from a client
        version, nmethods = connection.recv(2)

        # get available methods [0, 1, 2]
        methods = self.get_available_methods(nmethods, connection)

        # accept only USERNAME/PASSWORD auth
        if 2 not in set(methods):
            # close connection
            connection.close()
            return

        # send welcome message
        connection.sendall(bytes([SOCKS_VERSION, 2]))

        if not self.verify_credentials(connection):
            return

        # request (version=5)
        version, cmd, _, address_type = connection.recv(4)

        if address_type == 1:  # IPv4
            address = socket.inet_ntoa(connection.recv(4))
        elif address_type == 3:  # Domain name
            domain_length = connection.recv(1)[0]
            address = connection.recv(domain_length)
            address = socket.gethostbyname(address)

        # convert bytes to unsigned short array
        port = int.from_bytes(connection.recv(2), 'big', signed=False)

        try:
            if cmd == 1:  # CONNECT
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                #print("* Connected to {} {}".format(address, port))
            else:
                connection.close()

            addr = int.from_bytes(socket.inet_aton(bind_address[0]), 'big', signed=False)
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
            # return connection refused error
            reply = self.generate_failed_reply(address_type, 5)

        connection.sendall(reply)

        # establish data exchange
        if reply[1] == 0 and cmd == 1:
            self.botdev(connection, remote)

        connection.close()
    def generate_failed_reply(self, address_type, error_number):
            return b''.join([
            SOCKS_VERSION.to_bytes(1, 'big'),
            error_number.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            address_type.to_bytes(1, 'big'),
            int(0).to_bytes(4, 'big'),
            int(0).to_bytes(4, 'big')
        ])


    def verify_credentials(self, connection):
        version = ord(connection.recv(1)) # should be 1

        username_len = ord(connection.recv(1))
        username = connection.recv(username_len).decode('utf-8')

        password_len = ord(connection.recv(1))
        password = connection.recv(password_len).decode('utf-8')

        if username==self.username  and password==self.password :
            # success, status = 0
            response = bytes([version, 0])
            connection.sendall(response)
            return True

        # failure, status != 0
        response = bytes([version, 0xFF])
        connection.sendall(response)
        connection.close()
        return False


    def get_available_methods(self, nmethods, connection):
        methods = []
        for i in range(nmethods):
            methods.append(ord(connection.recv(1)))
        return methods

    def run(self, host, port):
        import time
        import socket
        import threading
        import select
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM )
        s.bind((host, port))
        s.listen()
        
        while True:
            conn, addr = s.accept()
            #print("* new connection from {}".format(addr))
            t = threading.Thread(target=self.handle_client, args=(conn,))
            t.start()
        

    def botdev(self, client, remote):
        
        while True:
            r, w, e = select.select([client, remote], [], [])
            if client in r or remote in r:
                if client in r:
                    global packet
                    global op
                    dataC = client.recv(99999)
                    global hide
                    hide =False
                    global recordmode,command,spy,invit_spam       
                    
                    if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >=820 and invit_spam==True :
                        try:
                        
                            for i in range(3):
                                threading.Thread(target=spam_invite , args=(dataC , remote)).start()
        
                        except:
                            pass
                        
                    if '1215' in dataC.hex()[0:4] and recordmode ==True:
                        
                        for i in range(10):
                            remote.send(dataC)
                        global spam
                        b = threading.Thread(target=spam, args=(remote,dataC))
                        b.start()


                    if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >= 141:
                        
                        hide = True

                    if '0515' in dataC.hex()[0:4] or '23.90.158.22' in str(remote) :
                        op = remote
                        
                    if remote.send(dataC) <= 0:
                        break
                if remote in r:
                    dataS = remote.recv(999999)
                    if '1200' in dataS.hex()[0:4] and command==True:
                        if b'/spy' in dataS:       #إختفاء
                            spy=True
                            threading.Thread(target=respons , args=[client,dataS,b"/Foxy",b"                "+"SpyON"]).start()
                        if b'/-spy' in dataS: 
                            spy=False
                            threading.Thread(target=respons , args=[client,dataS,b"/-Foxy",b"spyOFF"]).start()
                        if b'/spam' in dataS:     #سبام رسائل
                            recordmode=True
                            threading.Thread(target=respons , args=[client,dataS,b"/spam",b"Onlin"]).start()
                        if b'/-spam' in dataS:
                            recordmode=False
                            threading.Thread(target=respons , args=[client,dataS,b"/-spam",b"Offlin"]).start()
                        if b'/invi' in dataS:     #سبام دعوات
                            invit_spam=True
                            threading.Thread(target=respons , args=[client,dataS,b"/invi",b"ON"]).start()
                        if b'/-invi' in dataS:
                            invit_spam=False
                            threading.Thread(target=respons , args=[client,dataS,b"/invi",b"OFF"]).start()
    
#5سكواد
                    if '1200' in dataS.hex()[0:4] and '/5s' in dataS.hex()[0:900] and  command==True:
                    
                        op.send(bytes.fromhex("0503000001d01fb578313150905babcef51dd24ed75fd0a24b024bd1429646114bc22e604afd35a96fbc48710b2d9cfec4378287ec829e33a78608fd2dd138d4d24a19c00fbfdc9f15c77ff86d638b34de95bd886e3075e82d3f4a3888f9b6943463022c43fb90e229f0eaf8a788f6f766d891d99eb2c37b277144923212810b3c80d1c521790154ed270f5241adc136f2a22816e0bc84fcaf79386b27559de966aa788c184d35bbbfaa03a5f08746f8db0e73b2c91ec4515d61f689a0cad30a7cbd6c325151e879dabc43d506b3240abe41bc0d6b4416c18f68ef4af2d04c381be6bf586f6b25727c0c85c03a579137e4a6c602ef6d833dabdab3eba3a5266e5a4731fbfb1720b60f124cd8fd4fa26cc7a9fb6e0a218d8809f57b204d22fa97520aeb99007c7b71c709e53ecc688c9963e0786909152fa93f06dc93085468dae34e1609f33f7dee228fb058c6efd6846b50ac54db0aebb8f5bc2f6751f9e2886dbab41cbaf5a1d8cd88e6c13a2a2a56b613a2d32179dc3f781493a5027322ac0cb1a2d3c79d49fb12ed26230e1561df43d315a27be17b5debdba757803305252b5443f3d77cd319dde9c49a72c636d93d02bdd9597168f378aa6e41d0fd545abf8bc0883f3dac11ea27166683c7111a0f329bf6b6a5"))
                        threading.Thread(target=respons , args=[client,dataS,b"/Foxy2023",b"5 Sqoud"]).start()
                    if  '0500' in dataS.hex()[0:4] and hide == True :
                    
                    
                        if len(dataS.hex())<=30:
                            
                            hide =True
                        if len(dataS.hex())>=31:
                            packet = dataS
                            
                            hide = False
                    if  '0f00' in dataS.hex()[0:4] and spy==True :
                        client.send(packet)
                        

                    if '1808' in dataS.hex()[26:30]:
                        print('  the team capacity is full  stop ')

                    if client.send(dataS) <= 0:
                        break
                        print("#"*25)
                        print(data.hex())           

def respons( client , data ,text, respons):
    data=bytes(data)
    data = bytes.fromhex(data.hex().replace(text.hex(),respons.hex()))
    time.sleep(1.5)
    client.send((data))
                    
def spam_invite( data,remote):
    try:
        for i in range(300):
            remote.send(data)
    except:
        pass
    
def RIZAKYI_bot():
    try :
        Proxy().run('127.0.0.1',7000)
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

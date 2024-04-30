B = '''[1;30m'''
R = '''[1;31m'''
G = '''[1;32m'''
Y = '''[1;33m'''
Bl = '''[1;34m'''
P = '''[1;35m'''
C = '''[1;36m'''
W = '''[1;37m'''
OB = '''[40m'''
OR = '''[41m'''
OG = '''[42m'''
OY = '''[43m'''
OBl = '''[44m'''
OP = '''[45m'''
OC = '''[46m'''
OW = '''[47m'''
import datetime
import codecs
import random
import time
import socket
import threading
import select
import re
import requests
from datetime import datetime
global roomretst

def gen_squad(clisocks, packet: str):
        header = packet[0:62]
        lastpacket = packet[64:]
        squadcount = "04"

        NewSquadData = header + squadcount + lastpacket
        clisocks.send(bytes.fromhex(NewSquadData))

def gen_msg4(packet, content):
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

def gen_msgv3(packet , replay):

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
                sock.send(bytes.fromhex(gen_msg4(packet, content)))
                sock.send(bytes.fromhex(gen_msgv3(packet, content)))
        except Exception as e:
                ##print(e)
                pass
roomretst = False
gameplayed= 0
listt =[]
serversocket =None
remotesockett = None
clienttsocket =None
istarted = False
start =None
stop =b'\x03\x15\x00\x00\x00\x10\t\x1e\xb7N\xef9\xb7WN5\x96\x02\xb0g\x0c\xa8'
increase =False
socktion =None
SOCKS_VERSION = 5
packet =b''
full = False
#
####

####
import requests

def shorten_url(long_url):
    api_url = "https://cleanuri.com/api/v1/shorten"
    data = {"url": long_url}
    response = requests.post(api_url, data=data)
    if response.status_code == 200:
        return response.json()["result_url"]
    else:
        return None
import datetime
import requests

def infoplus(accountid ,regtion):    
    url = 'https://freefireapi.com.br/api/search_id?id={}&region={}'.format(accountid, regtion)
    response = requests.get(url)
    if response.status_code == 200:
        long_text = response.text
    else:
        pass
    # name     
    ap = '"nickname":'
    dp = '","'
    start_link2 = long_text.find(ap) + len(ap) + 1
    end_link2 = long_text.find(dp, start_link2)
    name = long_text[start_link2:end_link2]
    ##print(name)
    # level
    ap1 = 'level"'
    dp1 = ',"exp'
    start_link3 = long_text.find(ap1) + len(ap1) + 1
    end_link3 = long_text.find(dp1, start_link3)
    level = long_text[start_link3:end_link3]
    ##print(level)
    # exp
    ap4 = ',"exp"'
    dp4 = ',"'
    start_link42 = long_text.find(ap4) + len(ap4) + 1
    end_link4 = long_text.find(dp4, start_link42)
    exp = long_text[start_link42:end_link4]
    ##print(exp)
    # liked
    ap5 = ',"liked"'
    dp4 = ',"showRank'
    start_link5 = long_text.find(ap5) + len(ap5) + 1
    end_link5 = long_text.find(dp4, start_link5)
    liked = long_text[start_link5:end_link5]
    ##print(liked)
    # last login
    ap6 = 'lastLoginAt":'
    dp6 = '","csRa'
    start_link6 = long_text.find(ap6) + len(ap6) + 1
    end_link6 = long_text.find(dp6, start_link6)
    lastlogin_beta = long_text[start_link6:end_link6]
    timestamp = int(lastlogin_beta)
    date_time = datetime.datetime.utcfromtimestamp(timestamp)
    lastlogin = date_time
    ##print(lastlogin)
    # create accunt
    ap7 = 'createAt":'
    dp7 = '"},"'
    start_link7 = long_text.find(ap7) + len(ap7) + 1
    end_link7 = long_text.find(dp7, start_link7)
    creatlogi_beta = long_text[start_link7:end_link7]
    timestamp = int(creatlogi_beta)
    date_time2 = datetime.datetime.utcfromtimestamp(timestamp)
    creatlogin = date_time2
    ##print(creatlogin)
    # rank token
    ap14 = 'rankingPoints"'
    dp14 = ',"badgeCnt'
    start_link14 = long_text.find(ap14) + len(ap14) + 1
    end_link14 = long_text.find(dp14, start_link14)
    rank_token = long_text[start_link14:end_link14]
    ##print(rank_token)
    # rank number
    ap15 = '"rank"'
    dp15 = ',"rankingPoints'
    start_link15 = long_text.find(ap15) + len(ap15) + 1
    end_link15 = long_text.find(dp15, start_link15)
    rank_number = long_text[start_link15:end_link15]
    ##print(rank_number)
    # langue
    ap8 = '"language":'
    dp8 = '"'
    start_link8 = long_text.find(ap8) + len(ap8) + 1
    end_link8 = long_text.find(dp8, start_link8)
    langue = long_text[start_link8:end_link8]
    ##print(langue)
    # bio
    ap9 = '"signature":'
    dp9 = '","rankShow'
    if "signature" in long_text:
        
        start_link9 = long_text.find(ap9) + len(ap9) + 1
        end_link9 = long_text.find(dp9, start_link9)
        bio = long_text[start_link9:end_link9]
    else:
        bio = "No bio"
    ##print(bio)
    # clan id
    ap10 = '"clanId":'
    dp10 = '","capt'
    start_link10 = long_text.find(ap10) + len(ap10) + 1
    end_link10 = long_text.find(dp10, start_link10)
    guild_id = long_text[start_link10:end_link10]
    ##print(guild_id)
    # admin clan id
    ap11 = '"captainBasicInfo":{"accountId":'
    dp11 = '","nickname":'
    start_link12 = long_text.find(ap11) + len(ap11) + 1
    end_link12 = long_text.find(dp11, start_link12)
    admin_id = long_text[start_link12:end_link12]
    ##print(admin_id)
    # admin clan name
    ap12 = '{}","nickname":'.format(admin_id)
    dp12 = '","leve'
    start_link11 = long_text.find(ap12) + len(ap12) + 1
    end_link11 = long_text.find(dp12, start_link11)
    admin_name = long_text[start_link11:end_link11]
    ##print(admin_name)
    # clan level
    ap13 = 'clanLevel"'
    dp13 = ',"capacity'
    start_link13 = long_text.find(ap13) + len(ap13) + 1
    end_link13 = long_text.find(dp13, start_link13)
    clan_level = long_text[start_link13:end_link13]
    ##print(clan_level)
    # clan cpacty
    ap17 = 'capacity"'
    dp17 = ',"member'
    start_link17 = long_text.find(ap17) + len(ap17) + 1
    end_link17 = long_text.find(dp17, start_link17)
    clan_capacity = long_text[start_link17:end_link17]
    ##print(clan_capacity)
    # clan maxcapacity
    ap16 = 'memberNum"'
    dp16 = '},"cap'
    start_link16 = long_text.find(ap16) + len(ap16) + 1
    end_link16 = long_text.find(dp16, start_link16)
    clan_maxcapacity = long_text[start_link16:end_link16]
    
    #print(name)
    #print(level)
    #print(exp)
    #print(liked)
    #print(lastlogin)
    #print(creatlogin)
    #print(rank_token)
    #print(rank_number)
    #print(langue)
    #print(bio)
    #print(clan_level)
    #print(clan_capacity)
    #print(clan_maxcapacity)        
def getdate(playerid):
    global data,dc
    data = requests.get(f"http://88.198.53.59:19350/info/{playerid}").text
    dc = data[9:19]
    ##(data)

    try:
        old_date = datetime.strptime(dc, "%d/%m/%Y")
        now = datetime.now()
        delta = now - old_date
        years = delta.days // 365
        months = (delta.days % 365) // 30
        days = (delta.days % 365) % 30
        return f"--> {dc}\n\n{years} سـنـوات \n\n{months} شـهـور \n\n{days} يـوم "
    except:
        return f"??? سـنـوات \n\n??? شـهـور \n\n??? يـوم "
def getreg(Id):    
     
    url = "https://shop2game.com/api/auth/player_id_login"
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9,en;q=0.8",
        "Content-Type": "application/json",
        "Origin": "https://shop2game.com",
        "Referer": "https://shop2game.com/app",
        "sec-ch-ua": '"Google Chrome";v="111", "Not(A:Brand";v="8", "Chromium";v="111"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "Windows",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
        "x-datadome-clientid": "10BIK2pOeN3Cw42~iX48rEAd2OmRt6MZDJQsEeK5uMirIKyTLO2bV5Ku6~7pJl_3QOmDkJoSzDcAdCAC8J5WRG_fpqrU7crOEq0~_5oqbgJIuVFWkbuUPD~lUpzSweEa",
    }
    payload = {
        "app_id": 100067,
        "login_id": f"{Id}",
        "app_server_id": 0,
    }
    response = requests.post(url, headers=headers, json=payload)
    try:
        if response.status_code == 200:
            return response.json()['region']
        else:
            return(f"ERROR")
    except:
        return("Server unknown ??")

def getname(Id):    
    url = "https://shop2game.com/api/auth/player_id_login"
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9,en;q=0.8",
        "Content-Type": "application/json",
        "Origin": "https://shop2game.com",
        "Referer": "https://shop2game.com/app",
        "sec-ch-ua": '"Google Chrome";v="111", "Not(A:Brand";v="8", "Chromium";v="111"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "Windows",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
        "x-datadome-clientid": "10BIK2pOeN3Cw42~iX48rEAd2OmRt6MZDJQsEeK5uMirIKyTLO2bV5Ku6~7pJl_3QOmDkJoSzDcAdCAC8J5WRG_fpqrU7crOEq0~_5oqbgJIuVFWkbuUPD~lUpzSweEa",
    }
    payload = {
        "app_id": 100067,
        "login_id": f"{Id}",
        "app_server_id": 0,
    }
    response = requests.post(url, headers=headers, json=payload)
    try:
        if response.status_code == 200:
            return response.json()['nickname']
        else:
            return("ERROR")
    except:
        return("Name unknown??")


def get_status(Id):
    r= requests.get('https://ff.garena.com/api/antihack/check_banned?lang=en&uid={}'.format(Id)) 
    a = "0"
    try : 
        if  a in r.text :
            return("Account is Not ban")
        else: 
            return("Account is ban")
    except:
        return("Status unknown")
def get_inc(id):
    accountid = id
    url = 'https://vrxx1337.pythonanywhere.com/?id={}'.format(accountid)
    response = requests.get(url)
    if response.status_code == 200:
        long_text = response.text
    else:
        return("8c8d99a21b")
    ap = 'idenc":'
    dp = '","'
    start_link2 = long_text.find(ap) + len(ap) + 1
    end_link2 = long_text.find(dp, start_link2)
    iud = long_text[start_link2:end_link2]
    return(iud)
def gen_msgv2_clan(replay  , packet):
    replay  = replay.encode('utf-8')
    replay = replay.hex()
    hedar = packet[0:8]
    packetLength = packet[8:10] #
    paketBody = packet[10:32]
    pyloadbodyLength = packet[32:34]#
    pyloadbody2= packet[34:64]
    if "googleusercontent" in str(bytes.fromhex(packet)):
        pyloadlength = packet[64:68]#
        pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+68):]
    elif "https" in str(bytes.fromhex(packet)) and "googleusercontent" not in str(bytes.fromhex(packet)):
        ##("-------------------------")
        
        pyloadlength = packet[64:68]#
        pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+68):]
        ##(bytes.fromhex(pyloadlength))
        # #(bytes.fromhex(pyloadTile))

        ##("-------------------------")

    else:
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


import re

def gen_msgv2(replay  , packet):
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
    return finallyPacket

def inret():
    global hidd,packet1
    try:
        hidd.send(packet1)
    except:
        pass

def nret():
    global vispacket,visback
    try:
        visback.send(vispacket)
    except:
        pass

def sendi():
    global snv,dataC
    while True:
        if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >= 900:
            for i in range(400):
                snv.send(dataC)
                for k in range(1):
                    time.sleep(0.001)

            break

###

###
error = None
preventlag = False
sqlag = False
st = False
serversocket = None
clientsocket =None
op = None
pekto =None
inviteD=False
spampacket= b''
recordmode= False
sendpackt=False
back = False
spy = False
resasa =False
id_view = None
rolp = False
comand =False
mess = False
msgs =False
SOCKS_VERSION = 5
packet = b''
packet1 = b''
invite = None
invite = None
returntoroom = False
###





roomp = False
number = 0

def roompass():
    global roomp
    if roomp == True:
        return True
    else:
        return False

def roomst():
    if roompass() == True:
        try:
            return str(number)
            ##print(str(number))
        except:
            return "BYTE BOT"
def xmodz(xmod):

      for k in range(90000):
          xmod.send(b'\x0e\x15\x00\x00\x00P\xd6\xd5\x19\x00+\xdc\xc6M\xe8\xa4,\x1a\xae\xdf\\:\xaa\xcf|\xe6\x94\xef\xbf\xc1\xf1\x1f\x02h\t\xb6%\xe7\x93aM\xd1?\xfa8\xee\xccUO\xf3 \xa6\x1b\x8a\xc6\x96\x99\xa8\xeb^\xda\xb7;9\xe9\xd9\x10zP\xd5\xe0\x83\xa2\xbc\x8c\x01\xfb\xadd\xdb\xcek\x85\x81\xcdP')
          for l in range(1):
              time.sleep(0.05)


def lagroom(cli,lg):
            for I in range(10):
                
                time.sleep(1)
                cli.send(b'\x0e\x15\x00\x00\x00\x10\x02\x92L\xf4)[\xa9xk^\xca\xf6\x8a\x80~w')
                time.sleep(1)
                cli.send(lg)
#-
from time import sleep

global cmode
cmode = False
def crmode(value7):
    global cmode
    cmode = value7
    return cmode


def crazymode(keam,pckt1,pckt):
        for i in range(20):
        	time.sleep(1.5)
        	keam.send(pckt)
        	time.sleep(2)
        	keam.send(pckt1)
def randm(keam,pckt1,pckt):
        for i in range(3):
        	time.sleep(1)
        	keam.send(pckt)
        	time.sleep(1)
        	keam.send(pckt1)
#---------------------

def find_name_and_value(value):
    if value == 1000 or (value < 1050 and value > 1000):
        return "Brounze1", 1000
    elif value == 1050 or (value < 1150 and value > 1050):
        return "Brounze2", 1050
    elif value == 1150 or (value < 1250 and value > 1150):
        return "Brounze3", 1150
    elif value == 1250 or (value < 1350 and value > 1250):
        return "Silver1", 1250
    elif value == 1350 or (value < 1450 and value > 1350):
        return "Silver2", 1350
    elif value == 1450 or (value < 1550 and value > 1450):
        return "Silver3", 1450
    elif value == 1550 or (value < 1663 and value > 1550):
        return "Gold1", 1550
    elif value == 1663 or (value < 1788 and value > 1663):
        return "Gold2", 1663
    elif value == 1788 or (value < 1913 and value > 1788):
        return "Gold3", 1788
    elif value == 1913 or (value < 2038 and value > 1913):
        return "Gold4", 1913
    elif value == 2038 or (value < 2163 and value > 2038):
        return "Platinum1", 2038
    elif value == 2163 or (value < 2288 and value > 2163):
        return "Platinum2", 2163
    elif value == 2288 or (value < 2413 and value > 2288):
        return "Platinum3", 2288
    elif value == 2413 or (value < 2538 and value > 2413):
        return "Platinum4", 2413
    elif value == 2538 or (value < 2675 and value > 2538):
        return "Diamond1", 2538
    elif value == 2675 or (value < 2825 and value > 2675):
        return "Diamond2", 2675
    elif value == 2825 or (value < 2975 and value > 2825):
        return "Diamond3", 2825
    elif value == 2975 or (value < 3125 and value > 2975):
        return "Diamond4", 2975
    elif value == 3125 or value > 3125:
        return "Heroic", 3125
    else:
        return "Value not found", None
def stoplg(rsend,leg,resocket,clsocket):
   preventlag = False
   for i in range(1):
      time.sleep(2)
      for h in range(1):
         rsend.send(b'\x0e\x15\x00\x00\x00\x10\x02\x92L\xf4)[\xa9xk^\xca\xf6\x8a\x80~w')
         for t in range(1):
            time.sleep(2)
            for k in range(1):
               rsend.send(leg)

global spprspm
def spprspm(server,packet):
        while True:
            time.sleep(0.014)
            server.send(packet)
            if msgs == False:
                break

fivesq = False
def fivepe(value23):
    global fivesq
    fivesq = value23
    return fivesq



def runsnv():
    threading.Thread(target=sendi).start()

SOCKS_VERSION = 5


class Proxy:


    def __init__(self):
        self.username = "username"
        self.password = "username"
        self.packet = b''
        self.sendmode = 'client-0-'
        global connection
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
                ##(" connect to {} \n \n \n ".format(address))
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
         #   #(username,password)
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
        var =  0
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host, port))
        s.listen()

        while True:
            var =var+1
            conn, addr = s.accept()
            running = False
            t = threading.Thread(target=self.handle_client, args=(conn,))
            t.start()

    def botdev(self, client, remote, port):
        global op
        global back
        global pekto
        global x
        global o
        global k
        o = True
        k = False
        x = False
        global b
        b = False
        global c
        c = False
        idinfo = True

        yout1 = b"\x06\x00\x00\x00{\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*o\x08\x81\x80\x83\xb6\x01\x1a)[ffffff]\xd8\xb5\xd8\xa7\xd8\xa6\xd8\xaf\xe3\x85\xa4\xd8\xa7\xd9\x84\xd8\xa8\xd9\x87\xd8\xa7\xd8\xa6\xd9\x85[ffffff]2\x02ME@N\xb0\x01\x13\xb8\x01\xdc)\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\tAO'-'TEAM\xf0\x01\x01\xf8\x01\xdc\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x11\xd8\x02F"
        yout2 = b'\x06\x00\x00\x00|\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*p\x08\xd6\xd1\xb9(\x1a![ffffff]\xef\xbc\xa8\xef\xbc\xac\xe3\x85\xa4Hassone.[ffffff]2\x02ME@G\xb0\x01\x13\xb8\x01\xcf\x1e\xd8\x01\xcc\xd6\xd0\xad\x03\xe0\x01\xed\xdc\x8d\xae\x03\xea\x01\x1d\xef\xbc\xb4\xef\xbc\xa8\xef\xbc\xa5\xe3\x85\xa4\xef\xbc\xa8\xef\xbc\xa5\xef\xbc\xac\xef\xbc\xac\xe0\xbf\x90\xc2\xb9\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
        yout3 = b'\x06\x00\x00\x00x\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*l\x08\xe9\xa7\xe9\x1b\x1a [ffffff]DS\xe3\x85\xa4WAJIHANO\xe3\x85\xa4[ffffff]2\x02ME@Q\xb0\x01\x14\xb8\x01\xca2\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x10.DICTATORS\xe3\x85\xa4\xe2\x88\x9a\xf0\x01\x01\xf8\x01\xc4\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02+'
        yout4 = b'\x06\x00\x00\x00z\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*n\x08\xed\xd4\xa7\xa2\x02\x1a\x1f[ffffff]M8N\xe3\x85\xa4y\xe3\x85\xa4Fouad[ffffff]2\x02ME@O\xb0\x01\x13\xb8\x01\xa9#\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xdb\xdb\x8d\xae\x03\xea\x01\x0cGREAT\xe2\x80\xbfWALL\xf0\x01\x01\xf8\x01b\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\r\xd8\x023\xe0\x02\xc1\xb7\xf8\xb1\x03'
        yout5 = b"\x06\x00\x00\x00\x84\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*x\x08\xb6\xc0\xf1\xcc\x01\x1a'[ffffff]\xd9\x85\xd9\x84\xd9\x83\xd8\xa9*\xd9\x84\xd9\x85\xd8\xb9\xd9\x88\xd9\x82\xd9\x8a\xd9\x86[ffffff]2\x02ME@G\xb0\x01\x05\xb8\x01\x82\x0b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x15\xe9\xbf\x84\xef\xbc\xac\xef\xbc\xaf\xef\xbc\xb2\xef\xbc\xa4\xef\xbc\xb3\xe9\xbf\x84\xf0\x01\x01\xf8\x01>\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x05\xd8\x02\x0e"
        yout6 = b'\x06\x00\x00\x00\x8e\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x81\x01\x08\xeb\x98\x88\x8e\x01\x1a"[ffffff]OP\xe3\x85\xa4BNL\xe3\x85\xa4\xe2\x9a\xa1\xe3\x85\xa4*[ffffff]2\x02ME@R\xb0\x01\x10\xb8\x01\xce\x16\xd8\x01\x84\xf0\xd2\xad\x03\xe0\x01\xa8\xdb\x8d\xae\x03\xea\x01\x1f\xe1\xb4\x8f\xe1\xb4\xa0\xe1\xb4\x87\xca\x80\xe3\x85\xa4\xe1\xb4\x98\xe1\xb4\x8f\xe1\xb4\xa1\xe1\xb4\x87\xca\x80\xe2\x9a\xa1\xf0\x01\x01\xf8\x01A\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01\xe0\x02\xf3\x94\xf6\xb1\x03'
        yout7 = b"\x06\x00\x00\x00\x8e\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x81\x01\x08\xb0\xa4\xdb\x80\x01\x1a'[ffffff]\xd9\x85\xd9\x83\xd8\xa7\xd9\x81\xd8\xad\xd8\xa9.\xe2\x84\x93\xca\x99\xe3\x80\xb5..[ffffff]2\x02ME@T\xb0\x01\x13\xb8\x01\xfc$\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xc1\xdb\x8d\xae\x03\xea\x01\x1d\xef\xbc\xad\xef\xbc\xa1\xef\xbc\xa6\xef\xbc\xa9\xef\xbc\xa1\xe3\x85\xa4\xe2\x8e\xb0\xe2\x84\x93\xca\x99\xe2\x8e\xb1\xf0\x01\x01\xf8\x01\xdb\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0f\xd8\x02>"
        yout8 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xfd\x8a\xde\xb4\x02\x1a\x1f[ffffff]ITZ\xe4\xb8\xb6MOHA\xe3\x85\xa42M[ffffff]2\x02ME@C\xb0\x01\n\xb8\x01\xdf\x0f\xd8\x01\xac\xd8\xd0\xad\x03\xe0\x01\xf2\xdc\x8d\xae\x03\xea\x01\x15\xe3\x80\x9dITZ\xe3\x80\x9e\xe1\xb5\x97\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf8\x01\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0e\xd8\x026'
        yout9 = b'\x06\x00\x00\x00w\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*k\x08\xc6\x99\xddp\x1a\x1b[ffffff]HEROSHIIMA1[ffffff]2\x02ME@I\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1e\xef\xbc\xa8\xef\xbc\xa5\xef\xbc\xb2\xef\xbc\xaf\xef\xbc\xb3\xef\xbc\xa8\xef\xbc\xa9\xef\xbc\xad\xef\xbc\xa1\xef\xa3\xbf\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
        yout10 = b'\x06\x00\x00\x00p\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*d\x08\xde\x91\xb7Q\x1a\x1c[ffffff]SH\xe3\x85\xa4SHIMA|M[ffffff]2\x02ME@R\xb0\x01\x14\xb8\x01\xe7C\xd8\x01\xdd\xd6\xd0\xad\x03\xe0\x01\xca\xdb\x8d\xae\x03\xea\x01\tSH\xe3\x85\xa4Team\xf8\x014\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x11\xd8\x02G\xe0\x02\x89\xa0\xf8\xb1\x03'
        yout11 = b'\x06\x00\x00\x00h\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\\\x08\xa1\x9f\xb3\xf4\x01\x1a\x1b[ffffff]2JZ\xe3\x85\xa4POWER[ffffff]2\x02ME@M\xb0\x01\x13\xb8\x01\xa5(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xec\xdb\x8d\xae\x03\xf0\x01\x01\xf8\x01\x9a\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02.\xe0\x02\xb2\xe9\xf7\xb1\x03'
        yout12 = b'\x06\x00\x00\x00\x8f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x82\x01\x08\xaa\xe5\xa4\xe3\x01\x1a-[ffffff]\xe3\x85\xa4\xd8\xb4\xd9\x83\xd8\xa7\xd9\x8e\xd9\x83\xd9\x80\xd9\x8a\xe3\x80\x8e\xe2\x85\xb5\xe1\xb4\x98\xe3\x80\x8f[ffffff]2\x02ME@Q\xb0\x01\x13\xb8\x01\xf2*\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xaf\xdb\x8d\xae\x03\xea\x01\x15\xe2\x80\xa2\xe3\x85\xa4\xe2\x93\x8b\xe2\x92\xbe\xe2\x93\x85\xe3\x85\xa4\xe2\x80\xa2\xf8\x01q\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02e\xe0\x02\xa0\xf1\xf7\xb1\x03'
        yout14 = b'\x06\x00\x00\x00\x86\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*z\x08\xfd\x8b\xf4\xfa\x01\x1a$[ffffff]"\xd8\xaf\xd8\xb1\xd8\xa7\xd8\xba\xd9\x88\xd9\x86\xd9\x80\xd9\x88\xd9\x81"[ffffff]2\x02ME@F\xb0\x01\x13\xb8\x01\xec \xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe1\xb4\x98\xe1\xb4\x84\xe1\xb5\x80\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf0\x01\x01\xf8\x01\xb0\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x04\xd8\x02\t\xe0\x02\xf2\x94\xf6\xb1\x03'
        yout15 = b'\x06\x00\x00\x00\x7f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*s\x08\x90\xf6\x87\x15\x1a"[ffffff]V4\xe3\x85\xa4RIO\xe3\x85\xa46%\xe3\x85\xa4zt[ffffff]2\x02ME@M\xb0\x01\x13\xb8\x01\x95&\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb1\xdd\x8d\xae\x03\xea\x01\x0e\xe1\xb4\xa0\xe1\xb4\x80\xe1\xb4\x8d\xe1\xb4\x8f\xd1\x95\xf0\x01\x01\xf8\x01\xe2\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02^\xe0\x02\x85\xff\xf5\xb1\x03'
        yout16 = b'\x06\x00\x00\x00s\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*g\x08\xaa\x84\xc1r\x1a\x1f[ffffff]SA777RAWI\xe3\x85\xa4\xe3\x85\xa4[ffffff]2\x02ME@N\xb0\x01\x13\xb8\x01\xc8\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x0cSA7RAWI\xe3\x85\xa4TM\xf0\x01\x01\xf8\x01\xfe\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\t\xd8\x02 '
        yout17 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xe7\xbf\xb6\x8f\x01\x1a\x1c[ffffff]SVG.NINJA\xe2\xbc\xbd[ffffff]2\x02ME@I\xb0\x01\x13\xb8\x01\x94\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x85\xdb\x8d\xae\x03\xea\x01\x15\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4???\xe3\x85\xa4\xe3\x85\xa4\xf0\x01\x01\xf8\x01o\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02?'
        yout18 = b"\x06\x00\x00\x00\x9d\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x90\x01\x08\xa8\xe8\x91\xd7\x01\x1a.[ffffff]\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe4\xba\x97\xef\xbc\xb9\xef\xbc\xb4\xe3\x85\xa4[ffffff]2\x02ME@N\xb0\x01\x13\xb8\x01\x97'\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1e\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe2\x80\xa2\xef\xbc\xb9\xef\xbc\xb4\xe2\x9c\x93\xf0\x01\x01\xf8\x01\xab\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02@\xe0\x02\xe9\x80\xf8\xb1\x03"
        yout19 = b'\x06\x00\x00\x00r\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*f\x08\x9b\x94\xaa\r\x1a\x1c[ffffff]FARAMAWY_1M.[ffffff]2\x02ME@I\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe2\x80\xa2\xe3\x85\xa4STRONG\xe3\x85\xa4\xe2\x80\xa2\xf0\x01\x01\xf8\x01X\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
        yout20 = b'\x06\x00\x00\x00p\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*d\x08\xde\x91\xb7Q\x1a\x1c[ffffff]SH\xe3\x85\xa4SHIMA|M[ffffff]2\x02ME@R\xb0\x01\x14\xb8\x01\xe7C\xd8\x01\xdd\xd6\xd0\xad\x03\xe0\x01\xca\xdb\x8d\xae\x03\xea\x01\tSH\xe3\x85\xa4Team\xf8\x014\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x11\xd8\x02G\xe0\x02\x89\xa0\xf8\xb1\x03'
        yout21= b'\x06\x00\x00\x00h\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\\\x08\xa1\x9f\xb3\xf4\x01\x1a\x1b[ffffff]2JZ\xe3\x85\xa4POWER[ffffff]2\x02ME@M\xb0\x01\x13\xb8\x01\xa5(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xec\xdb\x8d\xae\x03\xf0\x01\x01\xf8\x01\x9a\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02.\xe0\x02\xb2\xe9\xf7\xb1\x03'
        yout22 = b'\x06\x00\x00\x00\x8f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x82\x01\x08\xaa\xe5\xa4\xe3\x01\x1a-[ffffff]\xe3\x85\xa4\xd8\xb4\xd9\x83\xd8\xa7\xd9\x8e\xd9\x83\xd9\x80\xd9\x8a\xe3\x80\x8e\xe2\x85\xb5\xe1\xb4\x98\xe3\x80\x8f[ffffff]2\x02ME@Q\xb0\x01\x13\xb8\x01\xf2*\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xaf\xdb\x8d\xae\x03\xea\x01\x15\xe2\x80\xa2\xe3\x85\xa4\xe2\x93\x8b\xe2\x92\xbe\xe2\x93\x85\xe3\x85\xa4\xe2\x80\xa2\xf8\x01q\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02e\xe0\x02\xa0\xf1\xf7\xb1\x03'
        yout23 = b'\x06\x00\x00\x00\x86\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*z\x08\xfd\x8b\xf4\xfa\x01\x1a$[ffffff]"\xd8\xaf\xd8\xb1\xd8\xa7\xd8\xba\xd9\x88\xd9\x86\xd9\x80\xd9\x88\xd9\x81"[ffffff]2\x02ME@F\xb0\x01\x13\xb8\x01\xec \xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe1\xb4\x98\xe1\xb4\x84\xe1\xb5\x80\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf0\x01\x01\xf8\x01\xb0\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x04\xd8\x02\t\xe0\x02\xf2\x94\xf6\xb1\x03'
        yout24 = b'\x06\x00\x00\x00s\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*g\x08\xaa\x84\xc1r\x1a\x1f[ffffff]SA777RAWI\xe3\x85\xa4\xe3\x85\xa4[ffffff]2\x02ME@N\xb0\x01\x13\xb8\x01\xc8\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x0cSA7RAWI\xe3\x85\xa4TM\xf0\x01\x01\xf8\x01\xfe\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\t\xd8\x02 '
        yout25 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xe7\xbf\xb6\x8f\x01\x1a\x1c[ffffff]SVG.NINJA\xe2\xbc\xbd[ffffff]2\x02ME@I\xb0\x01\x13\xb8\x01\x94\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x85\xdb\x8d\xae\x03\xea\x01\x15\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4???\xe3\x85\xa4\xe3\x85\xa4\xf0\x01\x01\xf8\x01o\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02?'
        yout26 = b"\x06\x00\x00\x00\x9d\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x90\x01\x08\xa8\xe8\x91\xd7\x01\x1a.[ffffff]\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe4\xba\x97\xef\xbc\xb9\xef\xbc\xb4\xe3\x85\xa4[ffffff]2\x02ME@N\xb0\x01\x13\xb8\x01\x97'\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1e\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe2\x80\xa2\xef\xbc\xb9\xef\xbc\xb4\xe2\x9c\x93\xf0\x01\x01\xf8\x01\xab\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02@\xe0\x02\xe9\x80\xf8\xb1\x03"
        yout27 = b'\x06\x00\x00\x00r\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*f\x08\x9b\x94\xaa\r\x1a\x1c[ffffff]FARAMAWY_1M.[ffffff]2\x02ME@I\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe2\x80\xa2\xe3\x85\xa4STRONG\xe3\x85\xa4\xe2\x80\xa2\xf0\x01\x01\xf8\x01X\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
        yout28 = b"\x06\x00\x00\x00\x82\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*v\x08\xaa\xdd\xf1'\x1a\x1d[ffffff]BM\xe3\x85\xa4ABDOU_YT[ffffff]2\x02ME@G\xb0\x01\x13\xb8\x01\xd4$\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1d\xe2\x80\xa2\xc9\xae\xe1\xb4\x87\xca\x9f\xca\x9f\xe1\xb4\x80\xca\x8d\xe1\xb4\x80\xd2\x93\xc9\xaa\xe1\xb4\x80\xc2\xb0\xf0\x01\x01\xf8\x01\x8e\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x07\xd8\x02\x16"
        yout29 = b'\x06\x00\x00\x00r\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*f\x08\x9a\xd6\xdcL\x1a-[ffffff]\xe1\xb4\x8d\xcd\xa1\xcd\x9co\xe3\x85\xa4\xef\xbc\xa8\xef\xbc\xa1\xef\xbc\xa6\xef\xbc\xa9\xef\xbc\xa4\xef\xbc\xa9[ffffff]2\x02ME@H\xb0\x01\x01\xb8\x01\xe8\x07\xea\x01\x15\xe1\xb4\x8d\xcd\xa1\xcd\x9co\xc9\xb4\xef\xbd\x93\xe1\xb4\x9b\xe1\xb4\x87\xca\x80\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
        yout30 = b'\x06\x00\x00\x00v\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*j\x08\xb6\x92\xa9\xc8\x01\x1a [ffffff]\xef\xbc\xaa\xef\xbc\xad\xef\xbc\xb2\xe3\x85\xa4200K[ffffff]2\x02ME@R\xb0\x01\x13\xb8\x01\xc3(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\n3KASH-TEAM\xf8\x012\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x06\xd8\x02\x13\xe0\x02\x89\xa0\xf8\xb1\x03'
        yout31 = b"\x06\x00\x00\x00\x92\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x85\x01\x08\xa2\xd3\xf4\x81\x07\x1a'[ffffff]\xd8\xb3\xd9\x80\xd9\x86\xd9\x80\xd8\xaf\xd8\xb1\xd9\x8a\xd9\x84\xd8\xa71M\xe3\x85\xa4[ffffff]2\x02ME@K\xb0\x01\x13\xb8\x01\xc1 \xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1a\xef\xbc\xad\xef\xbc\xa6\xef\xbc\x95\xef\xbc\xb2\xef\xbc\xa8\xe3\x85\xa4\xe1\xb4\xa0\xc9\xaa\xe1\xb4\x98\xf0\x01\x01\xf8\x01\x8c\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0e\xd8\x024\xe0\x02\x87\xff\xf5\xb1\x03"
        yout32 = b'\x06\x00\x00\x00|\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*p\x08\xe0\xe1\xdeu\x1a\x1a[ffffff]P1\xe3\x85\xa4Fahad[ffffff]2\x02ME@N\xb0\x01\x13\xb8\x01\xd0&\xd8\x01\xea\xd6\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1a\xe3\x85\xa4\xef\xbc\xb0\xef\xbc\xa8\xef\xbc\xaf\xef\xbc\xa5\xef\xbc\xae\xef\xbc\xa9\xef\xbc\xb8\xc2\xb9\xf0\x01\x01\xf8\x01\x9e\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0b\xd8\x02*'
        yout33 = b'\x06\x00\x00\x00\x82\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*v\x08\xc5\xcf\x94\x8b\x02\x1a\x18[ffffff]@EL9YSAR[ffffff]2\x02ME@P\xb0\x01\x13\xb8\x01\x86+\xd8\x01\xa2\xd7\xd0\xad\x03\xe0\x01\x89\xae\x8f\xae\x03\xea\x01\x1d-\xc9\xaa\xe1\xb4\x8d\xe1\xb4\x8d\xe1\xb4\x8f\xca\x80\xe1\xb4\x9b\xe1\xb4\x80\xca\x9fs\xe2\xac\x86\xef\xb8\x8f\xf8\x01j\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x14\xd8\x02\xe2\x02\xe0\x02\x9f\xf1\xf7\xb1\x03'
        yout34 = b'\x06\x00\x00\x00x\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*l\x08\xa9\x81\xe6^\x1a\x1e[ffffff]STRONG\xe3\x85\xa4CRONA[ffffff]2\x02ME@J\xb0\x01\x13\xb8\x01\xd8$\xd8\x01\xd8\xd6\xd0\xad\x03\xe0\x01\x92\xdb\x8d\xae\x03\xea\x01\x12\xe2\x80\xa2\xe3\x85\xa4STRONG\xe3\x85\xa4\xe2\x80\xa2\xf0\x01\x01\xf8\x01q\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x14\xd8\x02\xbc\x01'
        yout35 = b'\x06\x00\x00\x00\x7f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*s\x08\xeb\x8d\x97\xec\x01\x1a&[ffffff]\xd8\xb9\xd9\x80\xd9\x85\xd9\x80\xd8\xaf\xd9\x86\xd9\x8a\xd9\x80\xd8\xaa\xd9\x80\xd9\x88[ffffff]2\x02ME@F\xb0\x01\x13\xb8\x01\xd3\x1a\xd8\x01\xaf\xd7\xd0\xad\x03\xe0\x01\xf4\xdc\x8d\xae\x03\xea\x01\rOSIRIS\xe3\x85\xa4MASR\xf8\x01o\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02\\\xe0\x02\xf4\x94\xf6\xb1\x03'
        yout36 = b'\x06\x00\x00\x00\x7f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*s\x08\xb4\xff\xa3\xef\x01\x1a\x1c[ffffff]ZAIN_YT_500K[ffffff]2\x02ME@K\xb0\x01\x13\xb8\x01\xa3#\xd8\x01\xa2\xd7\xd0\xad\x03\xe0\x01\xbb\xdb\x8d\xae\x03\xea\x01\x1b\xe1\xb6\xbb\xe1\xb5\x83\xe1\xb6\xa4\xe1\xb6\xb0\xe3\x85\xa4\xe1\xb5\x97\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf0\x01\x01\xf8\x01\\\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0b\xd8\x02('
        yout37 = b'\x06\x00\x00\x00\x8f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x82\x01\x08\x86\xa7\x9e\xa7\x0b\x1a([ffffff]\xe2\x80\x94\xcd\x9e\xcd\x9f\xcd\x9e\xe2\x98\x85\xef\xbc\xa2\xef\xbc\xac\xef\xbc\xb2\xef\xbc\xb8[ffffff]2\x02ME@d\xb0\x01\x13\xb8\x01\xe3\x1c\xe0\x01\xf2\x83\x90\xae\x03\xea\x01!\xe3\x85\xa4\xef\xbc\xa2\xef\xbc\xac\xef\xbc\xb2\xef\xbc\xb8\xe3\x85\xa4\xef\xbc\xb4\xef\xbc\xa5\xef\xbc\xa1\xef\xbc\xad\xe3\x85\xa4\xf8\x01u\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02Y\xe0\x02\xc1\xb7\xf8\xb1\x03'
        yout38 = b'\x06\x00\x00\x00\x85\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*y\x08\xc3\xcf\xe5H\x1a([ffffff]\xe3\x85\xa4BEE\xe2\x9c\xbfSTO\xe3\x85\xa4\xe1\xb5\x80\xe1\xb4\xb5\xe1\xb4\xb7[ffffff]2\x02ME@Q\xb0\x01\x14\xb8\x01\xffP\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xc1\xdb\x8d\xae\x03\xea\x01\x15TIK\xe2\x9c\xbfTOK\xe1\xb5\x80\xe1\xb4\xb1\xe1\xb4\xac\xe1\xb4\xb9\xf0\x01\x01\xf8\x01\xc8\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02q'
        yout39 = b'\x06\x00\x00\x00\x94\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x87\x01\x08\x97\xd5\x9a.\x1a%[ffffff]\xd8\xb9\xd9\x86\xd9\x83\xd9\x88\xd8\xb4\xe1\xb4\x80\xc9\xb4\xe1\xb4\x8b\xe3\x85\xa4[ffffff]2\x02ME@P\xb0\x01\x13\xb8\x01\xe8(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1f\xe1\xb4\x80\xc9\xb4\xe1\xb4\x8b\xe1\xb4\x9c\xea\x9c\xb1\xca\x9c\xe3\x85\xa4\xe1\xb4\x9b\xe1\xb4\x87\xe1\xb4\x80\xe1\xb4\x8d\xf0\x01\x01\xf8\x01\xb6\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\n\xd8\x02"\xe0\x02\xf2\x94\xf6\xb1\x03'
        yout40 = b'\x06\x00\x00\x00\x8a\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*~\x08\xf7\xdf\xda\\\x1a/[ffffff]\xef\xbc\xa1\xef\xbc\xac\xef\xbc\xa8\xef\xbc\xaf\xef\xbc\xad\xef\xbc\xb3\xef\xbc\xa9_\xef\xbc\xb9\xef\xbc\xb4\xe2\x9c\x93[ffffff]2\x02ME@P\xb0\x01\x13\xb8\x01\xb9*\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xc1\xdb\x8d\xae\x03\xea\x01\x0cALHOMSI~TEAM\xf0\x01\x01\xf8\x01\x8e\x0e\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02S\xe0\x02\xc3\xb7\xf8\xb1\x03'
        yout41 = b'\x06\x00\x00\x00\x86\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*z\x08\xb5\xdd\xec\x8e\x01\x1a%[ffffff]\xd8\xa7\xd9\x88\xd9\x81\xe3\x80\x80\xd9\x85\xd9\x86\xd9\x83\xe3\x85\xa4\xe2\x9c\x93[ffffff]2\x02ME@K\xb0\x01\x13\xb8\x01\xdd#\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x18\xef\xbc\xaf\xef\xbc\xa6\xe3\x85\xa4\xef\xbc\xb4\xef\xbc\xa5\xef\xbc\xa1\xef\xbc\xad\xe3\x85\xa4\xf0\x01\x01\xf8\x01\xe8\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02Q'
        yout42 = b'\x06\x00\x00\x00\x8b\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x7f\x08\x81\xf4\xba\xf8\x01\x1a%[ffffff]\xef\xbc\xa7\xef\xbc\xa2\xe3\x85\xa4\xef\xbc\xae\xef\xbc\xaf\xef\xbc\x91\xe3\x81\x95[ffffff]2\x02ME@N\xb0\x01\x0c\xb8\x01\xbd\x11\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb1\xdd\x8d\xae\x03\xea\x01\x1a\xef\xbc\xa7\xef\xbc\xb2\xef\xbc\xa5\xef\xbc\xa1\xef\xbc\xb4__\xef\xbc\xa2\xef\xbc\xaf\xef\xbc\xb9\xf8\x018\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02-\xe0\x02\x85\xff\xf5\xb1\x03'
        yout43 = b'\x06\x00\x00\x00o\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*c\x08\xfb\x9d\xb9\xae\x06\x1a\x1c[ffffff]BT\xe3\x85\xa4BadroTV[ffffff]2\x02ME@@\xb0\x01\x13\xb8\x01\xe7\x1c\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x91\xdb\x8d\xae\x03\xea\x01\nBadro_TV_F\xf0\x01\x01\xf8\x01\x91\x1a\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\n\xd8\x02!'
        yout44 = b"\x06\x00\x00\x00s\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*g\x08\xc4\xe5\xe1>\x1a'[ffffff]\xd8\xb5\xd8\xa7\xd8\xa6\xd8\xaf~\xd8\xa7\xd9\x84\xd8\xba\xd9\x86\xd8\xa7\xd8\xa6\xd9\x85[ffffff]2\x02ME@J\xb0\x01\x14\xb8\x01\xceP\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x03Z7F\xf0\x01\x01\xf8\x01\xd0\x19\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x14\xd8\x02\x9c\x01"
        yout45 = b'\x06\x00\x00\x00\x85\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*y\x08\xfd\xa4\xa6i\x1a$[ffffff]\xd8\xb2\xd9\x8a\xd9\x80\xd8\xb1\xc9\xb4\xcc\xb67\xcc\xb6\xca\x80\xe3\x85\xa4[ffffff]2\x02ME@M\xb0\x01\x13\xb8\x01\xe1(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x19\xc2\xb7\xe3\x85\xa4\xe3\x85\xa4N\xe3\x85\xa47\xe3\x85\xa4R\xe3\x85\xa4\xe3\x85\xa4\xc2\xb7\xf0\x01\x01\xf8\x01\x8f\t\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02k'
        yout46 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xcc\xb9\xcc\xd4\x06\x1a"[ffffff]\xd8\xa8\xd9\x88\xd8\xad\xd8\xa7\xd9\x83\xd9\x80\xd9\x80\xd9\x80\xd9\x85[ffffff]2\x02ME@9\xb0\x01\x07\xb8\x01\xca\x0c\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x11*\xef\xbc\x97\xef\xbc\xaf\xef\xbc\xab\xef\xbc\xa1\xef\xbc\xad*\xf0\x01\x01\xf8\x01\xad\x05\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
        yout47 = b'\x06\x00\x00\x00e\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*Y\x08\xe8\xbd\xc9b\x1a [ffffff]\xe3\x80\x8cvip\xe3\x80\x8dDR999FF[ffffff]2\x02ME@Q\xb0\x01\x10\xb8\x01\x94\x16\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xf0\x01\x01\xf8\x01\xa0\x04\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02+'
        yout48 = b'\x06\x00\x00\x00\x82\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*v\x08\x86\xb7\x84\xf1\x01\x1a&[ffffff]\xd8\xa2\xd9\x86\xd9\x8a\xd9\x80\xd9\x80\xd9\x84\xd8\xa7\xce\x92\xe2\x92\x91\xe3\x85\xa4[ffffff]2\x02ME@Q\xb0\x01\x13\xb8\x01\x82)\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x13\xce\x92\xe2\x92\x91\xe3\x85\xa4MAFIA\xe3\x85\xa4\xef\xa3\xbf\xf0\x01\x01\xf8\x01\x95\x04\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02W'
        yout49 = b'\x06\x00\x00\x00u\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*i\x08\xb4\xbe\xde\x83\x02\x1a [ffffff]SPONGEBOB!\xe3\x85\xa4\xe4\xba\x97[ffffff]2\x02ME@N\xb0\x01\x14\xb8\x01\x842\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x96\xdb\x8d\xae\x03\xea\x01\x0cALHOMSI~TEAM\xf0\x01\x01\xf8\x01\xbd\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02{'
        yout50 = b'\x06\x00\x00\x00u\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*i\x08\xb4\xbe\xde\x83\x02\x1a [ffffff]SPONGEBOB!\xe3\x85\xa4\xe4\xba\x97[ffffff]2\x02ME@N\xb0\x01\x14\xb8\x01\x842\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x96\xdb\x8d\xae\x03\xea\x01\x0cALHOMSI~TEAM\xf0\x01\x01\xf8\x01\xbd\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02{'
        yout51 = b'\x06\x00\x00\x00z\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*n\x08\xed\xd4\xa7\xa2\x02\x1a\x1f[ffffff]M8N\xe3\x85\xa4y\xe3\x85\xa4Fouad[ffffff]2\x02ME@O\xb0\x01\x13\xb8\x01\xa9#\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xdb\xdb\x8d\xae\x03\xea\x01\x0cGREAT\xe2\x80\xbfWALL\xf0\x01\x01\xf8\x01b\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\r\xd8\x023\xe0\x02\xc1\xb7\xf8\xb1\x03'

        yout_list = [yout1,yout2,yout3,yout4,yout5,yout6,yout7,yout8,yout9,yout10,yout11,yout12,yout14,yout15,yout16,yout17,yout18,yout19,yout20,yout21,yout22,yout23,yout24,yout25,yout26,yout27,yout28,yout29,yout30,yout31,yout32,yout33,yout34,yout35,yout36,yout37,yout38,yout39,yout40,yout41,yout42,yout43,yout44,yout45,yout46,yout47,yout48,yout49,yout50,yout51]
        global cmodeinfo
        cmodeinfo = True

        global cmodeloop
        cmodeloop = False
        
        global random
        random = False
        global full


        global exitpacket
        global enterpacket
        exitpacket = b''
        enterpacket = b''
        idinfo = True
        global visible_ret
        global fivesq
        kema = False
        activation = True
        global roba
        packet0300 = True
        roba = 1
        stat = True
        global viback
        viback = False
        # 5 in group5
        restartsock = False
        ########
        global startspammsg
        startspammsg = False

        global lg_room
        lg_room = False

        global spam_invs
        spam_invs = False

        global fivesq
        fivesq = False


        global increaseL
        increaseL = False

        global inv_ret
        inv_ret = False

        global visible_ret
        visible_ret = False

        global add_yout
        add_yout = False
        global msg1
        msg1 = False
        ########

        while True:
            ######################################
            #spam messages

            global spamsg
            def spamsg(value):
                global startspammsg
                startspammsg = value
                return startspammsg
		    
            # lag room

#            global lagroomsw
#            def foxy( self , data_join):
#                global back
#                while back==True:
#                	self.op.send(data_join)
#                	time.sleep(9999.0)

            #spam invs

            global spam_invitations
            def spam_invitations(value3):
                global spam_invs
                spam_invs = value3
                return spam_invs


            # 5 in group5



            # crazymode



            # Level ++
            global level_increase
            def level_increase(value6):
                global increaseL
                increaseL = value6
                return increaseL





            global youtubers
            def youtubers(value42):
                global add_yout
                add_yout = value42
                return add_yout
                


            ######################################
            r, w, e = select.select([client, remote], [], [])
            global start
            global full
            global hidd
            if client in r or remote in r:
                global serversocket
                global remotesockett
                global clientsockett
                if client in r:
                    global team
                    global teams
                    global packett1
                    global levelplus
                    global packett
                    global visback
                    global vispacket
                    global dataC
                    dataC = client.recv(999999)

                    #####
                    global hide
                    hide =False
                    global id_view
                    global rolp
                    global mess
                    
                    global comand
                    global resasa
                    global msgs
                    global recordmode
                    global MainC
                    if port == 39699:
                    	MainC = client
                    if '0e15' in dataC.hex()[0:4] and len(dataC.hex()) == 44:
                        exitpacket = dataC
                    if '0e15' in dataC.hex()[0:4] and len(dataC.hex()) > 80 and len(dataC.hex()) < 180:
                        enterpacket = dataC
                        room = remote
                   
                    if '0515' in dataC.hex()[0:4]:
                        f=12
                    if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >= 141:
                        hide = True
                    if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >= 141  :
                    	self.data_join=dataC
                    if '0515' in dataC.hex()[0:4] and len(dataC.hex()) < 50:   #ENTER TO SQUAD
                       ##(dataC)
                       ##(dataC.hex())
                       ##(len(dataC.hex()))
                       self.data_back=dataC
                       packett1 = dataC
                       ##("ENTER TO SQUAD Def")
                    if '0515' in dataC.hex()[0:4] and 700 < len(dataC.hex()) < 1100:   #ENTER TO SQUAD
                       team = remote
                       teams = client
                       packett = dataC                    

                    if resasa ==True and '1215' in dataC.hex()[0:4]:
                      
                         while True:
                                            time.sleep(0.10)
                                            op.send(bytes.fromhex("0315000001c06c03e17766c196a7e5734b2ffc686550e2f36b0582a92cde34b8dd2fa1447f900cf94ed69fc8214ea2974452331d769dcc1ccfac654a5ac6cedd5c049e30c124a3790970ecc0f5937a841a6c61781ce368a854c6ea9d52ed3e585f9dae5b09c3a8f20f5616dcbf6b09866dde0ecd468f343bbcf8fc8e64e8a4baa04a0055429b80b7a9c3c9dcb1154cb59332ffe0ee01f2ea048357e3994e463248f86d00583617a191ea3a04ba6654c814f0d6cb62e132a68e633bb7dbc3f71dbdeba9eff0d2a67052c74e9ebfc5b31205274c2abfe1bd0d6ed9d6945ef548ed8c60848e4e79b43f4abff0db31cd216455f5d718dc4463c52c9c2453f52d0645bb14275167cd4dfc51dcd633d39a2dff56cea674351bbf1ed637677c05d203017bbf1cb5032cf02e298b800d625c998d49caadad1bf6899e37425b58a7c5171fc213647648422ae0e7fa57432cd9b2e03b2a333b9456c7de61e1af62c0bd1f66e1071ddd346c10c01ea92db82acd90f75964fecec88be8388bdd2a7b0e6e7cd5bbd425e54e0b7a54587bc975758dca65dcf1630090e23efdc62f8f82fadeeac71ba4ca68410d60b50a9d81140f6db1f2cc0bc54258ef0ca9e6377656a1985c468d812bde7ae1"))
                                           
                                            if resasa ==False:
                                                break
                                            
                    if msgs ==True:
                        if '1215' in dataC.hex()[0:4]:
                            for i in range(10):
                                remote.send(dataC)
                            global spprspm
                            b = threading.Thread(target=spprspm, args=(remote,dataC))
                            b.start()
                    #####
                    if port == 39698:
                            levelplus = remote
                    if  "39699" in str(remote) :
                    	self.op = remote
                    if '0515' in dataC.hex()[0:4] or '23.90.158.22' in str(remote) :
                        op = remote
                    if remote.send(dataC) <= 0:
                            break
                if remote in r:

                    ######
                    global hidr
                    global cliee
                    global lag
                    global newdataS
                    global newdataSofspam
                    global newdataSoffspam
                    global clieee
                    global backto
                    global actcode
                    global returntoroom
                    global newbackdataS
                    global getin
                    global spaminv
                    global spammsg
                    global preventlag
                    global sqlag
                    global ingroup5
                    global group5
                    global invite
                    global roomp
                    global number
                    global acctive
                    global invtoroom
                    global msgact
                    global lagscript
                    global lagmsg
                    global stoplag
                    global stopmsg
                    global cpy
                    global back
                   
                    ######
                    global full
                    #####


                    #####



                    global listt
                    global C
                    global istarted
                    global gameplayed
                    global packet
                    global socktion
                    global increase
                    global roomp
                    global roomretst
                    global number
                    global invtoroom
                    global invtoroompacket
                    global snv
                    global newdataS2
                    global packet1
                    dataS = remote.recv(999999)
                    if '0e00' in dataS.hex()[:4] and '0e15' in dataC.hex()[:4] and preventlag == True:
                            pass
                            #print()
                    else:

                        if increaseL == True:
                            threading.Thread(target=xmodz,args=(levelplus,)).start()
                            increaseL = False

                        if full == True:               
                            ##("Send info")                    
                            
                            full = False

                        if '0e15' in dataC.hex()[:4] and returntoroom ==True:
                            remote.send(lag)
                            returntoroom =False
                            clieee = remote
                            st =False
                        if '0e15' in dataC.hex()[:4]:
                            remotesockett = remote
                            clientsockett = client
                        if '0e15' in dataC.hex()[0:4] and 75 < len(dataC.hex()) < 180:
                            ##(dataC)
                            ##(len(dataC.hex()))
                            clieee = remote
                            lag = dataC
                                                 # /lag
                    

                        if lg_room == True:
                            preventlag =True
                            threading.Thread(target=lagroom,args=(clieee,lag)).start()
                            restartsock = True
                        if lg_room == False:
                            preventlag = False
                            if restartsock == True:
                                try:
                                    remotesockett.close()
                                    clientsockett.close()
                                except:
                                    pass
                                restartsock = False

                        try:
                            if '1200' in dataS.hex()[0:4] and b'/info' in dataS and comand == True: #/back
                                ##("Done")
                                backto = client
                                newbackdataS = dataS.hex()
                                full = True
                                ##(full)

                        except:
                            pass

                        if cmodeloop==True:
                            threading.Thread(target=crazymode,args=(team,packett1,packett)).start()
                        if cmode == False:
                            cmodeloop = False
                            

                        if  port == 39698:
                            invite = client
                            snv = remote


                        if startspammsg == True:     #/spam
                           recordmode = True


                        

                        if startspammsg == False: #/f
                            statues = False


                        if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >= 900 and b == True :
                                try:
                                    for i in range(200):
                                        try:
                                            remote.send(dataC)
                                        except:
                                            pass
                                        for k in range(1):
                                                time.sleep(0.001)
                                    b = False
                                    spam_invs = False
                                    remote.close()
                                    client.close()
                                except:
                                    #()
                                    b = False
                                    spam_invs = False
                                    remote.close()
                                    client.close()


                        if '0e00' in dataS.hex()[0:4]:
                           for i in range(10):
                               pattern = fr"x0{str(i)}(\d+)Z"
                               match = re.search(pattern, str(dataS))
                               if match:
                                   number = match.group(1)
                                   global romcode
                                   romcode = number
                                   ##print(romcode)
                                   ##print("go")
                                   break
                           if match:
                               pass
                           else:
                               if "OPENATTRIBUTESEXT" in str(dataS):
                                    pass

                        if spam_invs == True: #/i
                                b = True

                        if  '0500' in dataS.hex()[0:4] and hide == True:
                            mess = True
                            x = 0
                            if len(dataS.hex())<=30:
                                hide = True
                            if len(dataS.hex())>=25:
                                packet1 = dataS
                                hidd = client
                                hide = False
                        if "0f00" in dataC.hex()[0:4]:
                            print(Y)
                            print(dataS.hex())
                        if "0515" in dataC.hex()[0:4] and 1400 > len(dataC.hex()) >= 900:
                            visback = remote
                            vispacket = dataC
                            # 8c8d99a21b = My
                        passwords = ["8c8d99a21b"]
                        if b"code::ON" in dataS:
                        	newdataS2 = dataS.hex()
                        	getin = client
                        	global dataplus
                        	dataplus = newdataS2
                        	pasw = dataS.hex()[12:22]
                        	if pasw in passwords:
                        	    
                        	    try:
                        	        comand = True
                        	        getin.send(bytes.fromhex(gen_msgv2_clan(f"""[b][c][66FF00][Activated Bot]""",newdataS2)))
                        	    except:
                        	        pass
                        	else:
                        	    try:
                        	        getin.send(bytes.fromhex(gen_msgv2_clan(f"""[b][c][FF0000][Not Activated]""",newdataS2)))
                        	    except:
                        	        pass
                        if b"@FD5" in dataS and comand == True:
                            op.send(bytes.fromhex("0515000000301a55e2c4e0bb2b3e02f11b4f9f9e0b55ec9b15af7b8eec4273c32c67be0cb9d2fe3d0b12b2064841ba21001df8665703"))
                            
                             
#start klach squad
                        if b"@FD3" in dataS and comand == True:
                            op.send(bytes.fromhex("051500000020cdfdd29898d11f3510a1e346a000f194ae71b48153af0923a6b95c6ad5dfb394"))
#spam message
                        if b"@FDS" in dataS and comand == True:
                            msgs =True
                        if b"#FDS" in dataS and comand == True:
                            msgs =False
# spam invits
                        if b"@FDI" in dataS and comand == True:
                            spam_invs =True
                        if b"#FDI" in dataS and comand == True:
                            spam_invs =False
                        if b"@ANG_START" in dataS and comand == True:
                                newdataS2 = dataS.hex()
                                getin = client
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "Welcom To", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][FF00FF]PEGA[00FFFF]SUS V2", 0.2)).start()
                                time.sleep(0.3)
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c]Mode by [F7FE2E]FADAIⓋ", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[FF8000][b][c]Comands :", 0.2)).start()
                                time.sleep(0.3)
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), """@FD5 [00FFFF] in Squad 5""", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), """[b][c]@FD3 [d44904] in Squad 3""", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), """[b][c]@FDS[0000FF]Spam Messages""", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), """[b][c]@FDI [d97a5b]Spam invitations""", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), """[b][c]@FDNR[ff8345]Stay in Rome""", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), """[b][c]@FDB[8ffff2]Back last Squad""", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), """[b][c]#my[FF0000]Sensitive info""", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), """[b][c]@FDZF [26ed97]Super Mode""", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), """[b][c]PD@@id [FFFF00]General player info""", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), """[b][c]PD++id [f5f595]Advanced player info""", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), """[b][c]PD??id [ed91a5]Clan player info""", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), """[b][c]PD::id [66FF00]Ranked player info""", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), """[b][c]PD==id [c421ff]View Player bio""", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), """[b][c]@FDTnum[8878ff] Dances""", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), """[b][c]@FDRnum//id[ff7881] Anyone dance""", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), """[b][c]@FDYOT[f74b0c]Add youtubers""", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), """[b][c]@FDRK==id[e06363]Someone imitating dances """, 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), """[b][c]@FDPS[ed26b5]View Code Rome""", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), """[b][c]@FDTLS[FF8000]dances liste""", 0.2)).start()

                        if b'GroupID' in dataS and comand == True and mess ==True:
                            mess = False
                            id = dataplus[12:22]
                            dor = "120000083408*101220022aa71008*10*22890f5b62d98c5d5b63d98f5d5b666666666666d98f5d5b2b5d20d8a7d984d985d8b9d984d988d985d8a7d8aa0a0a5b626430363036d98f5dd985d8b9d984d988d985d8a7d8aa20d985d8aad982d8afd985d8a920d8b9d98620d984d8a7d8b9d8a80a5b666666666666d98f5d46442b2b69640a5b656430393039d98b5dd985d8b9d984d988d985d8a7d8aa20d8b9d8a7d985d8a920d8b9d98620d984d8a7d8b9d8a80a5b666666666666d98f5d4644404069640a5b623334663466d98f5dd985d8b9d984d988d985d8a7d8aa20d8aad8b5d986d98ad98120d984d8a7d8b9d8a80a5b666666666666d98f5d46443a3a69640a5b663031383531d98c5dd985d8b9d984d988d985d8a7d8aa20d8b1d8a7d8a8d8b7d8a920d984d8a7d8b9d8a8200a5b666666666666d98f5d46443f3f69640a5b643937313731d98f5dd8b9d8b1d8b620d8a8d8a7d98ad98820d984d8a7d8b9d8a80a5b666666666666d98f5d46443d3d69640a5b663061616161d98f5dd985d8b9d984d988d985d8a7d8aa20d8add8b3d8a7d8b3d8a920d8b9d98620d984d8a7d8b9d8a80a5b666666666666d98f5d406d790a5b656432313931d98c5d5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f0a0a2020202020202020205b666666666666d98f5d5b2b5d20d8a7d984d985d8acd985d988d8b9d8a90a0a5b626461323036d98c5d3520d8a3d8b4d8aed8a7d8b520d8a8d8a7d984d985d8acd985d988d8b9d8a90a5b666666666666d98f5d404644350a5b656463663231d9925d3420d8a3d8b4d8aed8a7d8b520d8a8d8a7d984d985d8acd985d988d8b9d8a90a5b666666666666d98f5d404644340a5b663265303739d98f5d3320d8a3d8b4d8aed8a7d8b520d8a8d8a7d984d985d8acd985d988d8b9d8a90a5b666666666666d98f5d404644330a5b656432313931d98c5d5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f0a0a2020202020202020205b666666666666d98f5d5b2b5d20d8a7d984d8a7d8b5d8afd982d8a7d8a1200a0a5b656436383231d98f5dd8a5d8b6d8a7d981d8a920d8a7d984d98ad8aad98ad988d8a8d8b1d8b220d984d984d8a3d8b5d8afd982d8a7d8a10a5b666666666666d98f5d404644594f540a5b656432313931d98c5d5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f0a0a2020202020202020205b666666666666d98f5d5b2b5d20d8a7d984d8b1d982d8b5d8a7d8aa200a0a5b316239313063d98c5dd8a7d984d8add8b5d988d98420d8b9d984d98920d8b1d982d8b5d8a7d8aa0a5b666666666666d98f5d40464454780a5b343666663265d98f5dd8a5d8acd8b9d98420d8a7d98a20d984d8a7d8b9d8a820d98ad8b1d982d8b50a5b666666666666d98f5d40464452782f2f69640a5b396465363137d98c5dd984d8a7d8b9d8a820d8a7d8aed8b120d98ad982d984d8af20d8b1d982d8b5d8a7d8aad9830a5b666666666666d98f5d40464443782f2f69640a5b383065643737d98f5dd982d8a7d8a6d985d8a920d8b1d982d8b5d8a7d8aa0a5b666666666666d98f5d404644544c530a5b656432313931d98c5d5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f0a0a2020202020202020205b666666666666d98f5d5b2b5d20d8a7d984d8b3d8a8d8a7d9850a0a5b626231616462d98c5dd8b3d8a8d8a7d98520d8afd8b9d988d8a7d8aa200a5b666666666666d98f5d404644490a5b643436336562d98c5dd8b3d8a8d8a7d98520d8b1d8b3d8a7d8a6d9840a5b666666666666d98f5d404644530a5b656432313931d98c5d5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f0a0a2020202020202020205b666666666666d98f5d5b2b5d20d8a7d984d8b3d983d988d8a7d8afd8a7d8aa0a0a5b323262356436d98f5dd8acd8b9d98420d986d981d8b3d98320d985d8aed981d98a20d8a8d8a7d984d8b3d983d988d8a7d8af0a5b666666666666d98f5d404644590a5b313866666666d98c5dd8a7d984d8b9d988d8afd8a920d984d8a2d8aed8b120d8b3d983d988d8a7d8af20d8b8d8a7d987d8b10a5b666666666666d98f5d404644420a5b366664396365d98f5dd985d986d8b920d8b7d8b1d8afd98320d985d98620d8b3d983d988d8a7d8af0a5b666666666666d98f5d4046445a460a5b613765386532d98c5dd8a5d8b6d8a7d981d8a920d8b4d8aed8b520d984d984d8b3d983d988d8a7d8af0a5b666666666666d98f5d404641442f2f69640a5b656432313931d98c5d5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f0a0a2020202020202020205b666666666666d98f5d5b2b5d20d8a7d984d8b1d988d985d8a7d8aa200a0a5b656233323135d98c5dd985d986d8b920d8b7d8b1d8afd98320d985d98620d8a7d984d8b1d988d985200a5b666666666666d98f5d4046444e520a5b663236653561d98c5dd8b9d8b1d8b620d983d984d985d8a920d8b3d8b120d8a7d984d8b1d988d9850a5b666666666666d98f5d40464450530a5b656432313931d98c5d5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f0a0a2020202020202020205b666666666666d98f5d205b2b5d20d8a7d984d985d982d8a8d8b1d8a9200a0a5b646231363136d98f5dd985d982d8a8d8b1d8a920d984d8a3d98a20d8b4d8aed8b520d8aad8b1d98ad8af200a5b666666666666d98f5d2040464d5554452f2f696428fcafe1af064a1f0a095a45452d544f4f4c531086db8dae0320c90142094e45575a4552424f545202656e6a600a5a68747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414367386f634b5930454f6b57703362383679524258466c613967704264734655684d5f724f454b393775424e46532d3d7339362d63100118017200"
                            raks = dor.replace('*', id)
                            client.send(bytes.fromhex(raks))
                            
                        if b"@FDTLS" in dataS and comand == True:
                                newdataS2 = dataS.hex()
                                getin = client
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][FF8000] قائمة رقصات", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][FF8000]num :", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][00ffff]رقصات مميزة :", 0.2)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]A1", 1.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]A2", 1.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]A3", 1.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]A4", 1.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]A5", 1.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]A6", 1.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]A7", 1.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]A8", 1.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]A9", 1.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][00ffff]رقصات أسلحة :", 1.5)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]B1", 2.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]B2", 2.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]B3", 2.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]B4", 2.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]B5", 2.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]B6", 2.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]B7", 2.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][00ffff]رقصات حيوانات :", 2.5)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]C1", 3.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]C2", 3.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]C3", 3.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]C4", 3.0)).start()
                                threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][90e30b]C5", 3.0)).start()
                        if b"@my" in dataS and comand == True:
                        	newdataS2 = dataplus
                        	hex_string = dataS.hex()
                        	getin = client
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][00ffff]معلومات حساسة...",newdataS2)))
                        	decoded_text = codecs.decode(hex_string, 'hex').decode('latin-1')
                        	long_text = decoded_text
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][F7FE2E][+] نوع الربط :",newdataS2)))
                        	if 'google' in long_text:
                        		getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][66FF00]Google accunt",newdataS2)))
                        		ap = 'https'
                        		dp = ''
                        		start_link2 = long_text.find(ap)
                        		end_link2 = long_text.find(dp, start_link2)
                        		link = long_text[start_link2:end_link2]
                        		short_url = shorten_url(link)
                        		getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][F7FE2E][+] رابط الحساب :",newdataS2)))
                        		getin.send(bytes.fromhex(gen_msgv2_clan(f"""{short_url}""",newdataS2)))
                        	if 'facebook' in long_text:
                        		getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][00FFFF]Facebook accunt",newdataS2)))
                        		ap = 'https'
                        		dp = ''
                        		start_link2 = long_text.find(ap)
                        		end_link2 = long_text.find(dp, start_link2)
                        		link = long_text[start_link2:end_link2]
                        		short_url = shorten_url(link)
                        		getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][F7FE2E][+] رابط الحساب :",newdataS2)))
                        		getin.send(bytes.fromhex(gen_msgv2_clan(f"""{short_url}""",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][FF00FF]PEGA[00FFFF]SUS V2",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c]developer by[F7FE2E]FADAIⓋ",newdataS2)))
                        if b"#my" in dataS and comand == True:
                        	newdataS2 = dataplus
                        	hex_string = dataS.hex()
                        	getin = client
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][00ffff]Sensitive information...",newdataS2)))
                        	decoded_text = codecs.decode(hex_string, 'hex').decode('latin-1')
                        	long_text = decoded_text
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][F7FE2E][+]accunt type :",newdataS2)))
                        	if 'google' in long_text:
                        		getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][66FF00]Google accunt",newdataS2)))
                        		ap = 'https'
                        		dp = ''
                        		start_link2 = long_text.find(ap)
                        		end_link2 = long_text.find(dp, start_link2)
                        		link = long_text[start_link2:end_link2]
                        		short_url = shorten_url(link)
                        		getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][F7FE2E][+] Accunt link :",newdataS2)))
                        		getin.send(bytes.fromhex(gen_msgv2_clan(f"""{short_url}""",newdataS2)))
                        	if 'facebook' in long_text:
                        		getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][00FFFF]Facebook accunt",newdataS2)))
                        		ap = 'https'
                        		dp = ''
                        		start_link2 = long_text.find(ap)
                        		end_link2 = long_text.find(dp, start_link2)
                        		link = long_text[start_link2:end_link2]
                        		short_url = shorten_url(link)
                        		getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][F7FE2E][+] Accunt link :",newdataS2)))
                        		getin.send(bytes.fromhex(gen_msgv2_clan(f"""{short_url}""",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][FF00FF]PEGA[00FFFF]SUS V2",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c] by[F7FE2E]FADAIⓋ",newdataS2)))

                        if b"@FDB" in dataS and comand == True:
                        	try:
                        		back= True
                        		threading.Thread(target=self.foxy , args=(self.data_join,)).start()
                        	except:
                        		pass
                        if b"@FDZF" in dataS and comand == True:
                        	try:
                        		threading.Thread(target=crazymode,args=(team,packett1,packett)).start()
                        	except:
                        		pass
                        if b"@FDRM" in dataS and comand == True:
                           try:
                           	threading.Thread(target=randm,args=(team,packett1,packett)).start()
                           except:
                           	pass
                        if b"@FDPS" in dataS and comand == True:
                        	newdataS2 = dataplus
                        	getin = client
                        	try:
                        	    getin.send(bytes.fromhex(gen_msgv2_clan(f"""[b][c][F7FE2E]Room password :""",newdataS2)))
                        	    getin.send(bytes.fromhex(gen_msgv2_clan(f"""[b][c][66FF00]{romcode}""",newdataS2)))
                        	    getin.send(bytes.fromhex(gen_msgv2_clan(f"""[b][c][FF00FF]PEGA[00FFFF]SUS V2""",newdataS2)))
                        	except:
                        		threading.Thread(target=send_msg, args=(client, dataS.hex(), "[b][c][FF00FF]Error !", 0.2)).start()
                        if b"@FDNR" in dataS and comand == True:
                            threading.Thread(target=lagroom,args=(clieee,lag)).start()
                        if b"PD@@" in dataS and comand == True:
                        	newdataS2 = dataS.hex()
                        	getin = client
                        	text = str(bytes.fromhex(newdataS2))
                        	match = re.search(r'\@\@(.*?)\(', text)
                        	number=match.group(1)
                        
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[FFC800][b][c]Player info..",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[FF8000ً][b][c][+]Player id :",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[66FF00ٌ][b][c]{number}",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[FF8000ً][b][c][+]Player Name :",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[66FF00ٌ][b][c]{getname(number)}",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[FF8000ً][b][c][+] Player Status :",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[66FF00ٌ][b][c]{get_status(number)}",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[FF8000ً][b][c][+] Player Server",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[66FF00ٌ][b][c]{getreg(number)}",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][FF00FF]PEGA[00FFFF]SUS V2",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c]developer by[F7FE2E]FADAIⓋ",newdataS2)))
                        if b"PD@@" in dataS and comand == True:
                        	newdataS2 = dataS.hex()
                        	getin = client
                        	text = str(bytes.fromhex(newdataS2))
                        	match = re.search(r'\@\@(.*?)\(', text)
                        	number=match.group(1)
                        
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[FFC800][b][c]معلومات عامة...",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[FF8000ً][b][c][+] الأيدي :",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[66FF00ٌ][b][c]{number}",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[FF8000ً][b][c][+] الإسم :",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[66FF00ٌ][b][c]{getname(number)}",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[FF8000ً][b][c][+] الحالة :",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[66FF00ٌ][b][c]{get_status(number)}",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[FF8000ً][b][c][+] المنطقة :",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[66FF00ٌ][b][c]{getreg(number)}",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][FF00FF]PEGA[00FFFF]SUS V2",newdataS2)))
                        	getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c]developer by[F7FE2E]FADAIⓋ",newdataS2)))
                        if b"FD++" in dataS and comand == True:
                            
                            newdataS2 = dataS.hex()
                            getin = client
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][66FF00]معلومات متقدمة للاعب :",newdataS2)))
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\+\+(.*?)\(', text)
                            number=match.group(1)
                            regtion = getreg(number)
                            url = 'https://freefireapi.com.br/api/search_id?id={}&region={}'.format(number, regtion)
                            response = requests.get(url)
                            if response.status_code == 200:
                                long_text = response.text
                                #print(long_text)
                            else:
                                pass
                            #print(P)
                            # level
                            ap1 = 'level"'
                            dp1 = ',"'
                            start_link3 = long_text.find(ap1) + len(ap1) + 1
                            end_link3 = long_text.find(dp1, start_link3)
                            level = long_text[start_link3:end_link3]
                        	# name
                            ap = '"nickname":'
                            dp = '","'
                            start_link2 = long_text.find(ap) + len(ap) + 1
                            end_link2 = long_text.find(dp, start_link2)
                            name = long_text[start_link2:end_link2]
                            # exp
                            ap4 = ',"exp"'
                            dp4 = ',"'
                            start_link42 = long_text.find(ap4) + len(ap4) + 1
                            end_link4 = long_text.find(dp4, start_link42)
                            exp = long_text[start_link42:end_link4]
                            ##print(exp)
                            # liked
                            ap5 = ',"liked"'
                            dp4 = ',"'
                            start_link5 = long_text.find(ap5) + len(ap5) + 1
                            end_link5 = long_text.find(dp4, start_link5)
                            liked = long_text[start_link5:end_link5]
                            ##print(liked)
                            # last login
                            ap6 = 'lastLoginAt":'
                            dp6 = '",'
                            start_link6 = long_text.find(ap6) + len(ap6) + 1
                            end_link6 = long_text.find(dp6, start_link6)
                            lastlogin_beta = long_text[start_link6:end_link6]
                            timestamp = int(lastlogin_beta)
                            date_time = datetime.datetime.utcfromtimestamp(timestamp)
                            lastlogin = date_time
                            ##print(lastlogin)
                            # create accunt
                            ap7 = 'createAt":'
                            dp7 = '"},"'
                            start_link7 = long_text.find(ap7) + len(ap7) + 1
                            end_link7 = long_text.find(dp7, start_link7)
                            creatlogi_beta = long_text[start_link7:end_link7]
                            timestamp = int(creatlogi_beta)
                            date_time2 = datetime.datetime.utcfromtimestamp(timestamp)
                            creatlogin = date_time2
                            #print(G)
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff0000]إسم :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][f5f595]{name}",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff0000]مستوى  :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][f5f595]{level}",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff0000]EXP شارات :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][f5f595]{exp}",newdataS2)))                   
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff0000]إعجابات:",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][f5f595]{liked}",newdataS2)))                       
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff0000]إنشاء الحساب في :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c]{creatlogin}",newdataS2)))               
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff0000]آخر ظهور :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c]{lastlogin}",newdataS2)))                       
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][FF00FF]PEGA[FFFF00]SUS V2",newdataS2)))            
                        if b"@FDNROM" in dataS and comand == True:
                            threading.Thread(target=lagroom,args=(clieee,lag)).start()
                        if b"PD++" in dataS and comand == True:
                            
                            newdataS2 = dataS.hex()
                            getin = client
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][66FF00]Advanced Player info :",newdataS2)))
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\+\+(.*?)\(', text)
                            number=match.group(1)
                            regtion = getreg(number)
                            url = 'https://freefireapi.com.br/api/search_id?id={}&region={}'.format(number, regtion)
                            response = requests.get(url)
                            if response.status_code == 200:
                                long_text = response.text
                                #print(long_text)
                            else:
                                pass
                            #print(P)
                            # level
                            ap1 = 'level"'
                            dp1 = ',"'
                            start_link3 = long_text.find(ap1) + len(ap1) + 1
                            end_link3 = long_text.find(dp1, start_link3)
                            level = long_text[start_link3:end_link3]
                        	# name
                            ap = '"nickname":'
                            dp = '","'
                            start_link2 = long_text.find(ap) + len(ap) + 1
                            end_link2 = long_text.find(dp, start_link2)
                            name = long_text[start_link2:end_link2]
                            # exp
                            ap4 = ',"exp"'
                            dp4 = ',"'
                            start_link42 = long_text.find(ap4) + len(ap4) + 1
                            end_link4 = long_text.find(dp4, start_link42)
                            exp = long_text[start_link42:end_link4]
                            ##print(exp)
                            # liked
                            ap5 = ',"liked"'
                            dp4 = ',"'
                            start_link5 = long_text.find(ap5) + len(ap5) + 1
                            end_link5 = long_text.find(dp4, start_link5)
                            liked = long_text[start_link5:end_link5]
                            ##print(liked)
                            # last login
                            ap6 = 'lastLoginAt":'
                            dp6 = '",'
                            start_link6 = long_text.find(ap6) + len(ap6) + 1
                            end_link6 = long_text.find(dp6, start_link6)
                            lastlogin_beta = long_text[start_link6:end_link6]
                            timestamp = int(lastlogin_beta)
                            date_time = datetime.datetime.utcfromtimestamp(timestamp)
                            lastlogin = date_time
                            ##print(lastlogin)
                            # create accunt
                            ap7 = 'createAt":'
                            dp7 = '"},"'
                            start_link7 = long_text.find(ap7) + len(ap7) + 1
                            end_link7 = long_text.find(dp7, start_link7)
                            creatlogi_beta = long_text[start_link7:end_link7]
                            timestamp = int(creatlogi_beta)
                            date_time2 = datetime.datetime.utcfromtimestamp(timestamp)
                            creatlogin = date_time2
                            #print(G)
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff0000]Name :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][f5f595]{name}",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff0000]Level :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][f5f595]{level}",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff0000]Exp :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][f5f595]{exp}",newdataS2)))                   
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff0000]Liked :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][f5f595]{liked}",newdataS2)))                       
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff0000]Create Accunt :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c]{creatlogin}",newdataS2)))               
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff0000]Last Login :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c]{lastlogin}",newdataS2)))                       
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][FF00FF]PEGA[FFFF00]SUS V2",newdataS2)))
                        if b"FD==" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            getin = client
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][26ed97]بايو لاعب :",newdataS2)))
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\=\=(.*?)\(', text)
                            number = match.group(1)
                            regtion = getreg(number)
                            url = 'https://freefireapi.com.br/api/search_id?id={}&region={}'.format(number, regtion)
                            response = requests.get(url)
                            if response.status_code == 200:
                                long_text = response.text
                                #print(long_text)
                            else:
                                pass
                            
                            ap9 = '"signature":'
                            dp9 = '","rankShow'
                            if "signature" in long_text:
                                start_link9 = long_text.find(ap9) + len(ap9) + 1
                                end_link9 = long_text.find(dp9, start_link9)
                                bio = long_text[start_link9:end_link9]
                            else:
                                bio = "No bio"
                            #print(bio)
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"{bio}",newdataS2)))
                        if b"PD==" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            getin = client
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][26ed97]Bio Player :",newdataS2)))
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\=\=(.*?)\(', text)
                            number = match.group(1)
                            regtion = getreg(number)
                            url = 'https://freefireapi.com.br/api/search_id?id={}&region={}'.format(number, regtion)
                            response = requests.get(url)
                            if response.status_code == 200:
                                long_text = response.text
                                #print(long_text)
                            else:
                                pass
                            
                            ap9 = '"signature":'
                            dp9 = '","rankShow'
                            if "signature" in long_text:
                                start_link9 = long_text.find(ap9) + len(ap9) + 1
                                end_link9 = long_text.find(dp9, start_link9)
                                bio = long_text[start_link9:end_link9]
                            else:
                                bio = "No bio"
                            #print(bio)
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"{bio}",newdataS2)))
                        if b"FD??" in dataS and comand == True:
                            
                            newdataS2 = dataS.hex()
                            getin = client
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][FF0000]معلومات رابطة لاعب :",newdataS2)))
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\?\?(.*?)\(', text)
                            number=match.group(1)
                            regtion = getreg(number)
                            url = 'https://freefireapi.com.br/api/search_id?id={}&region={}'.format(number, regtion)
                            response = requests.get(url)
                            if response.status_code == 200:
                                long_text = response.text
                            else:
                                pass
                            ap10 = '"clanId":'
                            dp10 = '","capt'
                            start_link10 = long_text.find(ap10) + len(ap10) + 1
                            end_link10 = long_text.find(dp10, start_link10)
                            guild_id = long_text[start_link10:end_link10]
                            ##print(guild_id)
                            # admin clan id
                            ap11 = '"captainBasicInfo":{"accountId":'
                            dp11 = '","nickname":'
                            start_link12 = long_text.find(ap11) + len(ap11) + 1
                            end_link12 = long_text.find(dp11, start_link12)
                            admin_id = long_text[start_link12:end_link12]
                            ##print(admin_id)
                            # admin clan name
                            ap12 = '{}","nickname":'.format(admin_id)
                            dp12 = '","leve'
                            start_link11 = long_text.find(ap12) + len(ap12) + 1
                            end_link11 = long_text.find(dp12, start_link11)
                            admin_name = long_text[start_link11:end_link11]
                            ##print(admin_name)
                            # clan level
                            ap13 = 'clanLevel"'
                            dp13 = ',"capacity'
                            start_link13 = long_text.find(ap13) + len(ap13) + 1
                            end_link13 = long_text.find(dp13, start_link13)
                            clan_level = long_text[start_link13:end_link13]
                            ##print(clan_level)
                            # clan cpacty
                            ap17 = 'capacity"'
                            dp17 = ',"member'
                            start_link17 = long_text.find(ap17) + len(ap17) + 1
                            end_link17 = long_text.find(dp17, start_link17)
                            clan_capacity = long_text[start_link17:end_link17]
                            ##print(clan_capacity)
                            # clan maxcapacity
                            ap16 = 'memberNum"'
                            dp16 = '},"cap'
                            start_link16 = long_text.find(ap16) + len(ap16) + 1
                            end_link16 = long_text.find(dp16, start_link16)
                            clan_maxcapacity = long_text[start_link16:end_link16]        
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ffff00]الأيدي :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff9191]{guild_id}",newdataS2)))                             
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ffff00]المستوى :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff9191]{clan_level}",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ffff00]عدد الاعبين :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff9191]{clan_maxcapacity}",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ffff00]الحد الأقصى للاعبين :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff9191]{clan_capacity}",newdataS2)))        
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ffff00]أيدي المالك :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff9191]{admin_id}",newdataS2)))                                                      
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ffff00]إسم المالك :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff9191]{admin_name}",newdataS2)))                       

                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][FF00FF]PEGA[FFFF00]SUS V2",newdataS2)))
                        if b"PD??" in dataS and comand == True:
                            
                            newdataS2 = dataS.hex()
                            getin = client
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][FF0000]Player Clan info :",newdataS2)))
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\?\?(.*?)\(', text)
                            number=match.group(1)
                            regtion = getreg(number)
                            url = 'https://freefireapi.com.br/api/search_id?id={}&region={}'.format(number, regtion)
                            response = requests.get(url)
                            if response.status_code == 200:
                                long_text = response.text
                            else:
                                pass
                            ap10 = '"clanId":'
                            dp10 = '","capt'
                            start_link10 = long_text.find(ap10) + len(ap10) + 1
                            end_link10 = long_text.find(dp10, start_link10)
                            guild_id = long_text[start_link10:end_link10]
                            ##print(guild_id)
                            # admin clan id
                            ap11 = '"captainBasicInfo":{"accountId":'
                            dp11 = '","nickname":'
                            start_link12 = long_text.find(ap11) + len(ap11) + 1
                            end_link12 = long_text.find(dp11, start_link12)
                            admin_id = long_text[start_link12:end_link12]
                            ##print(admin_id)
                            # admin clan name
                            ap12 = '{}","nickname":'.format(admin_id)
                            dp12 = '","leve'
                            start_link11 = long_text.find(ap12) + len(ap12) + 1
                            end_link11 = long_text.find(dp12, start_link11)
                            admin_name = long_text[start_link11:end_link11]
                            ##print(admin_name)
                            # clan level
                            ap13 = 'clanLevel"'
                            dp13 = ',"capacity'
                            start_link13 = long_text.find(ap13) + len(ap13) + 1
                            end_link13 = long_text.find(dp13, start_link13)
                            clan_level = long_text[start_link13:end_link13]
                            ##print(clan_level)
                            # clan cpacty
                            ap17 = 'capacity"'
                            dp17 = ',"member'
                            start_link17 = long_text.find(ap17) + len(ap17) + 1
                            end_link17 = long_text.find(dp17, start_link17)
                            clan_capacity = long_text[start_link17:end_link17]
                            ##print(clan_capacity)
                            # clan maxcapacity
                            ap16 = 'memberNum"'
                            dp16 = '},"cap'
                            start_link16 = long_text.find(ap16) + len(ap16) + 1
                            end_link16 = long_text.find(dp16, start_link16)
                            clan_maxcapacity = long_text[start_link16:end_link16]        
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ffff00]id clan :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff9191]{guild_id}",newdataS2)))                             
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ffff00]Level :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff9191]{clan_level}",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ffff00]Current capacity :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff9191]{clan_maxcapacity}",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ffff00]Max Capacity :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff9191]{clan_capacity}",newdataS2)))        
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ffff00]Admin id :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff9191]{admin_id}",newdataS2)))                                                      
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ffff00]Admin Name :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][ff9191]{admin_name}",newdataS2)))                       

                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][FF00FF]PEGA[FFFF00]SUS V2",newdataS2)))
                        if b"FD::" in dataS and comand == True:
                            
                            newdataS2 = dataS.hex()
                            getin = client
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][FFFF00]Player rating info :",newdataS2)))
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\:\:(.*?)\(', text)
                            number=match.group(1)
                            regtion = getreg(number)
                            url = 'https://freefireapi.com.br/api/search_id?id={}&region={}'.format(number, regtion)
                            response = requests.get(url)
                            if response.status_code == 200:
                                long_text = response.text
                            else:
                                pass
                            ap14 = 'rankingPoints"'
                            dp14 = ',"badgeCnt'
                            start_link14 = long_text.find(ap14) + len(ap14) + 1
                            end_link14 = long_text.find(dp14, start_link14)
                            rank_token = long_text[start_link14:end_link14]
                            ##print(rank_token)
                            # rank number
                            ap15 = '"rank"'
                            dp15 = ',"rankingPoints'
                            start_link15 = long_text.find(ap15) + len(ap15) + 1
                            end_link15 = long_text.find(dp15, start_link15)
                            rank_number = long_text[start_link15:end_link15]
                            ap19 = 'seasonId"'
                            dp19 = ',"'
                            start_link19 = long_text.find(ap19) + len(ap19) + 1
                            end_link19 = long_text.find(dp19, start_link19)
                            mosim = long_text[start_link19:end_link19]
                            value = int(rank_token)
                            name, value = find_name_and_value(value)
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][66FF00]الموسم :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][8ffff2]{mosim}",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][66FF00]التصنيف :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][8ffff2]{name}",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][66FF00]نقاط تصنيف  :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][8ffff2]{rank_token}",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][66FF00]الرتبة في المنطقة :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][8ffff2]{rank_number}",newdataS2)))                            
                        if b"PD::" in dataS and comand == True:
                            
                            newdataS2 = dataS.hex()
                            getin = client
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][FFFF00]معلومات تصنيف لاعب :",newdataS2)))
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\:\:(.*?)\(', text)
                            number=match.group(1)
                            regtion = getreg(number)
                            url = 'https://freefireapi.com.br/api/search_id?id={}&region={}'.format(number, regtion)
                            response = requests.get(url)
                            if response.status_code == 200:
                                long_text = response.text
                            else:
                                pass
                            ap14 = 'rankingPoints"'
                            dp14 = ',"badgeCnt'
                            start_link14 = long_text.find(ap14) + len(ap14) + 1
                            end_link14 = long_text.find(dp14, start_link14)
                            rank_token = long_text[start_link14:end_link14]
                            ##print(rank_token)
                            # rank number
                            ap15 = '"rank"'
                            dp15 = ',"rankingPoints'
                            start_link15 = long_text.find(ap15) + len(ap15) + 1
                            end_link15 = long_text.find(dp15, start_link15)
                            rank_number = long_text[start_link15:end_link15]
                            ap19 = 'seasonId"'
                            dp19 = ',"'
                            start_link19 = long_text.find(ap19) + len(ap19) + 1
                            end_link19 = long_text.find(dp19, start_link19)
                            mosim = long_text[start_link19:end_link19]
                            value = int(rank_token)
                            name, value = find_name_and_value(value)
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][66FF00]season :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][8ffff2]{mosim}",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][66FF00]Category :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][8ffff2]{name}",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][66FF00]Rank Point :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][8ffff2]{rank_token}",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][66FF00]Rank in region :",newdataS2)))
                            getin.send(bytes.fromhex(gen_msgv2_clan(f"[b][c][8ffff2]{rank_number}",newdataS2)))
                        if b"@FDYOT" in dataS and comand == True:
                            add_yout =True
                        if b"@FDRK==" in dataS and comand == True:                            
                            newdataS2 = dataS.hex()
                            rolp = True
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\=\=(.*?)\(', text)
                            number=match.group(1)
                            id_view = get_inc(number)
                            
                        if "050000002008" in dataS.hex()[0:12] and rolp == True:
                            print(C)
                            print("Send.....")

                            ap1 = '050000002008'
                            dp1 = '100520162a1408'
                            start_link3 = long_text.find(ap1) + len(ap1) + 1
                            end_link3 = long_text.find(dp1, start_link3)
                            id_ooooadmin = long_text[start_link3:end_link3]
                            id_admin= dataS.hex()[12:22]
                            dor = dataS.hex()
                            raks = dor.replace(id_admin, id_view)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDTA1" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*1088b3bbb1032a0608*"
                            
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                            
                        if b"@FDTA2" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*1098fbb8b1032a0608*"
                            
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))

                        if b"@FDTA3" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*109bfbb8b1032a0608*"
                            
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDTA4" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10d2c2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDTA5" in dataS and comand == True:

                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10dcc2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDTA6" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10bbfbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDTA7" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*109284bbb1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))  
                        if b"@FDTA8" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*109cfbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDTA9" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10aefcbab1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))

                        if b"@FDTB1" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10fffab8b1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDTB2" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10ff8bbbb1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDTB3" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*1095fbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDTB4" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*108bfbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))


                        if b"@FDTB5" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10edbabbb1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDTB6" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10a2fbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDTB7" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*1084fbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                            # HAYA
                        if b"@FDTC1" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10b9cabbb1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDTC2" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10ca9bbbb1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDTC3" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*109e84bbb1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDTC4" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*109684bbb1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDTC5" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10d6c2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDRA1//" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*1088b3bbb1032a0608*"
                            
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDRA2//" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*1098fbb8b1032a0608*"
                            
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDRA3//" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*109bfbb8b1032a0608*"
                            
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDRA4//" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*10d2c2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDRA5//" in dataS and comand == True:

                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*10dcc2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDRA6//" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*10bbfbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDRA7//" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*109284bbb1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))  
                        if b"@FDRA8//" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*109cfbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDRA9//" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*10aefcbab1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))

                        if b"@FDRB1//" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*10fffab8b1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDRB2//" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*10ff8bbbb1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDRB3//" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*1095fbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDRB4//" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*108bfbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))


                        if b"@FDRB5//" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*10edbabbb1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDRB6//" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*10a2fbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDRB7//" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*1084fbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                            # haya
                        if b"@FDRC1//" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*10b9cabbb1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDRC2//" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*10ca9bbbb1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDRC3//" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*109e84bbb1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDRC4//" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*109684bbb1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if b"@FDRC5//" in dataS and comand == True:
                            newdataS2 = dataS.hex()
                            text = str(bytes.fromhex(newdataS2))
                            match = re.search(r'\/\/(.*?)\(', text)
                            number=match.group(1)
                            accountid = number
                            id = get_inc(accountid)
                            dor = "050000002008*100520162a1408*10d6c2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                        if '0e00' in dataS.hex()[0:4] and roomretst == True and "http" in str(dataS):

                            invtoroom = client
                            invtoroompacket = dataS
                        try:
                            

                            pass
                                               
                        except:
                            pass
                        if msg1 ==True:
                                    random_variable = random.choice([ms11, ms12, ms13])
                                    remote.send(random_variable)
                                  
                            #    if msg1 ==False:
                              #      break
                        if add_yout == True:
                            add_yout = False
                            from time import sleep
                            try:
                                for h in yout_list:
                                    MainC.send(h)
                                    sleep(0.2)
                            except:
                                pass
                        if b'/ret' in dataS and '1200' in dataS.hex()[0:4]:
                           clieee.send(lag)
                        if client.send(dataS) <= 0:
                            break
    def foxy( self , data_join):
        global back
        while back==True:
            self.op.send(data_join)
            time.sleep(9999.0)        
def startt():
        Proxy().runs('127.0.0.1',7000)
startt()
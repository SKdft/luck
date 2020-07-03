import subprocess

def popen(cmd):
    try:
        popen = subprocess.Popen(cmd,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 bufsize=-1)
        out,err = popen.communicate()
        out = out.decode('gbk')
        print('std_out:{0}'.format(out))
        print('returncode:{0}'.format(str(popen.returncode)))
    except BaseException as e:
        return e
cmd1 = r'dir'
popen(cmd1)
#cmd = r'nmap -sS -O -sV -iL url2.txt -p 80,8080,443 -v -T4 -Pn -oA result'

#popen(cmd)
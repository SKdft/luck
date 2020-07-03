import subprocess
import os
import time
import csv
import re
import requests
import sys
import pandas as pd

filelist=[]
host_port_dict={}

GBK = 'gbk'
UTF8 = 'utf-8'
current_encoding = GBK
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

def read_csv(url):
    dic = {}
    ip_list = []
    with open(url,'r',encoding='UTF-8') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            col1 = row[7]
            col2 = row[10]
            if re.findall(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", col2):
                if col2 not in ip_list:
                    ip_list.append(col2)
                    dic[row[7]]=col2
            else:
                pass
#                print("IP invaild!")
        csvfile.close()
        return dic

#循环检测oneforall的result文件夹下有无本次域名扫描的csv文件
def csv_to_ip():
    dic = []
    while True:
        time.sleep(3)
        for root, dirs, files in os.walk(r"C:\Users\Admin\Desktop\自收集安全工具\渗透测试\扫描探测\OneForAll\results", topdown=False):
            for name in files:
                str = os.path.join(root, name)
                if str.split('.')[-1] == 'csv' and domain in str:
                    filelist.append(str)
                    break;

        break
    if len(filelist) >= 1:
        print("OK!")
        print(filelist[0])
        dic = read_csv(filelist[0])
        return dic
    else:
        print("Not find!")

def result_url_txt(dic):
    f = open(r"C:\Users\Admin\Desktop\自收集安全工具\渗透测试\扫描探测\OneForAll\results\url.txt",'w')
    item = dic.values()
    for x in item:
        newline = x + '\n'
        f.write(newline)
    f.close()

#windows版本
def result_to_xlsx():
    host_port_dict1 = {}
    log = open("result.gnmap", "r")
    xls = open("output.csv", "a")
    xls.write("IP,port,status,protocol,service,version\n")
    for line in log.readlines():
        if line.startswith("#") or line.endswith("Status: Up\n"):
            continue
        result = line.split(" ")
        # print result
        host = result[1]
        # print host
        port_info = line.split("Ports: ")[1]
        # print port_info[0]
        port_info = port_info.split("/, ")
        print(port_info)
        for i in port_info:
            j = i.split("/")
        # print j
            output = host + "," + j[0] + "," + j[1] + "," + j[2] + "," + j[4] + "," + j[6] + "\n"
            #存储主机IP:端口   后续模拟get请求访问使用
            host_port_dict1[host] = j[0]
            xls.write(output)
    return host_port_dict1

def get_request(dict):
    f = open(r"C:\Users\Admin\Desktop\自收集安全工具\渗透测试\扫描探测\OneForAll\results\fina_result.txt", 'w')
    port_list = [80,443,8080]
    for i in dict.keys():
        for port in port_list:
            url = "http://{0}:{1}".format(i,port)
            print("request url :{0}".format(url))
            try:
                req = requests.get(url,timeout=5)
                time.sleep(1)
                # print(len(req.text))
                # print(req.text)
                print("{0} --- {1} --- status:{2} --- length:{3}".format(i,port,req.status_code,len(req.text)))
                newline = "{0} --- {1} --- status:{2} --- length:{3}".format(i,port,req.status_code,len(req.text)) + '\n'
                f.write(newline)
            except OSError:
                pass
            continue
    f.close()


#oneforall路径为:C:\Users\Admin\Desktop\自收集安全工具\渗透测试\扫描探测\OneForAll\results
domain = r'ly.com'

cmd = r'python C:\Users\Admin\Desktop\自收集安全工具\渗透测试\扫描探测\OneForAll\oneforall.py --target {0} run'.format(domain)
#执行oneforall得到子域名、IP结果
popen(cmd)

#获得相关ip列表
dic = csv_to_ip()
#print("Vaild IP list is:{0}".format(dic))

result_url_txt(dic)

#通过nmap获得相关IP服务器端口开放情况
cmd2 = r'nmap -sS -O -sV -iL url.txt -p 80,8080,443 -v -T4 -Pn -oA result'
popen(cmd2)

host_port_dict = result_to_xlsx()
get_request(host_port_dict)
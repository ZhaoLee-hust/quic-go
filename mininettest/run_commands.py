import os
import argparse
import time
from threading import Thread

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='args')
    parser.add_argument('--FECScheme',
                        '-fs',
                        dest='FECScheme',
                        type=str,
                        default='rs',
                        help='Default FECScheme.')

    args = parser.parse_args()

    

    s1 = '/home/zhaolee/workplace/mininet/util/m' + " 's1' "
    client = '/home/zhaolee/workplace/mininet/util/m' + " 'client' "
    server = '/home/zhaolee/workplace/mininet/util/m' + " 'server' "

    quic = '/home/zhaolee/go/src/github.com/lucas-clemente/quic-go/'
    quic_client = quic + 'example/client_benchmarker/'
    quic_server = quic + 'example/server/'
    pwd = '/home/zhaolee/workplace/PythonWork/mininettest/'
    build_go = 'go build main.go'

    # 10MB,file2
    httpdir = 'https://10.0.0.2:6121/file2'


    ## build client main并且移动到当前文件夹
    # build_main = 'go build %smain.go'%(quic_client)
    # os.system(build_main)

    ## 复制
    copy_main = 'cp %smain %s'%(quic_client, pwd)
    os.system(copy_main)
    os.system('sudo mv main main-client')

    ## build server main并且移动到当前文件夹
    # build_main = 'go build %smain.go'%(quic_server)
    # os.system(build_main)

    ## 复制
    copy_main = ('cp %smain %s')%(quic_server, pwd)
    os.system(copy_main)
    os.system('sudo mv main main-server')

    # dir = Dirs()
    # LossRate = [0]
    LossRate = [0,1,2,3,4,5]
    # Latency = [20,21]
    Latency = [20]
    limit = 1000
    rate = 20
    # reorder = [1,3,5,7,9]


    for loss in LossRate:
        for delay in Latency:
            # fs=args.FECScheme
            print("Running with new config fs=%s,limit=%d, lossrate=%d, latency=%d"%(args.FECScheme,limit,loss,delay))
            
            # 设置丢包、时延
            bashFile = "./scripts/TC_NETEM.bash %d %d %d %d"%(limit, delay, loss, rate)
            os.system(s1 + bashFile)

            # 运行 server
            log_file_name = 'serverlog_loss=%d_delay=%d_limit=%d_rate=%d.txt'%(loss,delay,limit,rate)
            server_cmd = ('%s ./main-server -u -rc c -o %s')%(server,log_file_name)
            t1 = Thread(target=os.system, args=(server_cmd,))

            # 运行client进行文件请求
            log_file_name = 'clientlog_loss=%d_delay=%d_limit=%d_rate=%d.txt'%(loss,delay,limit,rate)
            client_cmd = ('%s ./main-client -o %s %s ')%(client,log_file_name,httpdir)
            t2 = Thread(target=os.system, args=(client_cmd,))

            t1.start()
            t2.start()

            t2.join()
            # time.sleep(2)
            print('\n')
            # 获取server的PID并杀死
            # res = os.popen('ps -A | grep main')
            # os.system("ps -ef | grep main-server | grep -v grep | awk '{print $2}' | xargs kill")
            os.system('killall main-server')

            




# class Dirs():
#     def __init__(self) -> None:
#         self.SetDirsForQuicGo()
#         self.SetDirsforMininet()

#     def SetDirsForQuicGo(self):
#         # 项目路径
#         self.quicgo_dir = '/home/zhaolee/go/src/github.com/lucas-clemente/quic-go/'
#         # 服务端路径
#         self.server_dir = self.quicgo_dir + 'example/server/'
#         # 客户端路径
#         self.client_dir = self.quicgo_dir + 'example/client_benchmarker/'
#         # 指定服务器路径、端口号、文件名
#         self.port = '6121'
#         self.httpdir = 'https://127.0.0.1'
#         self.filename = 'file3'
    
#     def SetDirsforMininet(self):
#         # 项目路径
#         self.mPath = '/home/zhaolee/workplace/mininet/util/m'
#         self.pwd = '/home/zhaolee/workplace/PythonWork/mininettest/'

#     def RunMininet(self):
#         # 运行mininet的cmd命令
#         os.system('cd %s && sudo python basicTopo.py'%self.pwd)

#     def SetLossAndDelay(self,bashFile):
#         os.system(self.mPath + " s1 " + bashFile)

#     def BuildAndMoveClient(self):
#         os.system('cd '+ self.client_dir + ' && ' + 'go build main.go')
#         os.system('sudo cp '+ self.client_dir + 'main ' + self.pwd)
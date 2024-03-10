from mininet.topo import Topo
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import OVSBridge, Host
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.util import dumpNodeConnections

def setup_environment():
    # Create a network object.
    net = Mininet(topo=DoubleConnTopo(), switch=OVSBridge,controller=None)
    # net = Mininet(host=CPULimitedHost, link=TCLink)
    server = net.get("server")
    client = net.get("client")
    s1 = net.get("s1")

    server.setIP("10.0.0.2", intf="server-eth0")
    client.setIP("10.0.0.1", intf="client-eth0")

    # 设置丢包、延时均为0
    s1.cmd("./scripts/TC_NETEM.bash %d %d %d %d"%(5000,0,0,20))
    # s2.cmd("./scripts/tc_s2.bash")

    return net

class DoubleConnTopo(Topo):

    def build(self):
        # Add hosts and switches
        client = self.addHost("client")
        server = self.addHost("server")
        s1 = self.addSwitch('s1')


        # Add links
        self.addLink(s1, client)
        self.addLink(s1, server)
        # self.addLink(s0, h0, bw=10, delay='5ms',max_queue_size=1000, loss=10, use_htb=True)
        # the topo is like client <-> s1 <-> s2 <-> server


if __name__ == '__main__':
    setLogLevel('info')
    NET = setup_environment()
    # net = setup_environment()
    NET.start()

    
    print ("\nDumping host connections")
    dumpNodeConnections(NET.hosts)
    print("--------------------------\n")

    print ("\nTesting network connectivity")
    NET.pingAll()
    print("--------------------------\n")

    CLI(NET)
    NET.stop()
















# from mininet.topo import Topo
# from mininet.cli import CLI
# from mininet.net import Mininet
# from mininet.node import OVSBridge, Host
# # from psutil import cpu_count
# from mininet.log import setLogLevel, info
# from mininet.util import dumpNodeConnections

# def setup_environment():
#     net = Mininet(topo=DoubleConnTopo(), switch=OVSBridge, controller=None)
#     server = net.get("server")
#     client = net.get("client")
#     s1 = net.get("s1")

#     server.setIP("10.0.0.20", intf="server-eth0")
#     client.setIP("10.0.0.1", intf="client-eth0")
    
#     # client.cmd("./scripts/client_routing.bash")
#     # client.cmd("./scripts/tc_client.bash")

#     # server.cmd("./scripts/server_routing.bash")
#     # server.cmd("./scripts/tc_server.bash")

#     s1.cmd("./scripts/tc_s1.bash")

#     return net


# class DoubleConnTopo(Topo):

#     def build(self):
#         client = self.addHost("client")
#         server = self.addHost("server")
#         s1 = self.addSwitch('s1')
#         self.addLink(s1, client)
#         self.addLink(s1, server)

# def perfTest():
#     "Create network and run simple performance test"
#     net = setup_environment()
#     net.start()
#     print ("Dumping host connections")
#     dumpNodeConnections(net.hosts)
#     print ("Testing network connectivity")
#     net.pingAll()
#     print ("Testing bandwidth between hosts")
#     h1, h2, s1 = net.get('client', 'server','s1')

# # #===============  s1.cmd                ./scripts/set_bw_delay_loss.bash 10   100   10 
# # # ===============client.cmd                        ./scripts/client_set_bw_delay_loss.bash   10   100   10 

# #     bw=1000
# #     loss =0.000002
# #     rtt=1
# # #     # s1.cmd("./scripts/set_bw_delay_loss.bash %d  %d  %f" % (bw, int((rtt) / 2), loss))# 对称链路，两边的延时是，两边设置一样的丢包率，一样的，带宽也一样

# #     h1.cmd("./scripts/client_set_bw_delay_loss.bash %f  %f  %f" %(bw, float((rtt) / 2), loss) )
# #     h2.cmd("./scripts/server_set_bw_delay_loss.bash %f  %f  %f" %(bw, float((rtt) / 2), loss) )

#     # net.iperf((h1, h2),seconds=5)
#     # net.iperf((h1, h2),l4Type='UDP',udpBw='100M',seconds=5)
#     CLI(net)
#     print("CLI running")
#     net.stop()


# if __name__ == '__main__':
#     setLogLevel('debug')
#     # 带宽的测试，添加语句
#     perfTest()

#     #延时和丢包率的测试，设置的语句，有效的改变了时延和丢包率，:mtr 全称 my traceroute，是一个把 ping 和 traceroute 合并到一个程序的网络诊断工具
#     #例子：mtr 10.0.0.20

#     # NET = setup_environment()
#     # NET.start()
#     # CLI(NET)
#     # NET.stop()

# #     client = NET.get("client")
# #     server = NET.get("server")
# #     s1 = NET.get("s1")
# #     bw=10
# #     loss =0.2 
# #     rtt=100
# # #===============  s1.cmd                ./scripts/set_bw_delay_loss.bash 10   100   10 
# # # ===============client.cmd                        ./scripts/client_set_bw_delay_loss.bash   10   100   10 
# #     s1.cmd("./scripts/set_bw_delay_loss.bash %d  %d  %f" % (bw, int((rtt) / 2), loss))# 对称链路，两边的延时是，两边设置一样的丢包率，一样的，带宽也一样
# #     client.cmd("./scripts/client_set_bw_delay_loss.bash %d  %d  %f" %(bw, int((rtt) / 2), loss) )





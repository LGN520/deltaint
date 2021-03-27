import socket
import parse
# import processor
import redis
import sys

from scapy.all import get_if_addr, get_if_list

ifs = get_if_list()
print(ifs, flush=True)

class receive():
    def sniff(self):
        s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW,
                          socket.htons(0x0003))
        r = redis.Redis(unix_socket_path='/var/run/redis/redis.sock')
        src_ip = get_if_addr("eth0") # dstip?
        parse1 = parse.parse()

        while True:
            data = s.recv(2048)
            if not data:
                print("Client has exist")
                break
            rs = parse1.filter(data)
            # rs= dip,dmac,port1,port2,port3,delta_time # srcip? srcmac? port_list, delta_time
            if rs != None:
                # Convert each element in port_list into str
                for i in range(len(rs[2])):
                    rs[2][i] = str(rs[2][i])
                fmt=[src_ip,rs[0],rs[1]]+rs[2]
                key="+".join(fmt)
                value=rs[3]
                print("{}, {}".format(key, value))
                r.set(key,value)
                r.pexpire(key,3000)
        s.close()


if __name__ == "__main__":
    receive1 = receive()
    receive1.sniff()

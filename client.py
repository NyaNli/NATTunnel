import nattunnel
import time

# 114.114.114.114:53 -> UDP:Remote:53
clientUDP = nattunnel.NATTunnelClient(
    server_addr='localhost', 
    localaddr=('114.114.114.114', 53), 
    remoteport=53, 
    protocol=nattunnel.PROTOCOL_UDP)
clientUDP.start()

# localhost:80 -> TCP:Remote:8899
clientTCP = nattunnel.NATTunnelClient(
    server_addr='localhost', 
    localaddr=('localhost', 80), 
    remoteport=8899, 
    protocol=nattunnel.PROTOCOL_TCP)
clientTCP.start()

try:
    while True and clientUDP.isAlive() and clientTCP.isAlive():
        time.sleep(1)
except:
    clientUDP.stop()
    clientTCP.stop()
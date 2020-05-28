import nattunnel
import time

server = nattunnel.NATTunnelServer()
server.start()
print('NATTunnel Server started.')

try:
    while True:
        time.sleep(1)
except:
    server.stop()
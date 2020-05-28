class Packet:

    OP_BIND_TCP = 0
    OP_BIND_UDP = 1
    OP_CLIENT_CONN = 2
    OP_CLIENT_SEND = 3
    OP_CLIENT_DISCONN = 4
    OP_PING = 5
    OP_PONG = 6

    def __init__(self, head : bytes = None):
        self.op : int = 0
        self.client_ip : str = '0.0.0.0'
        self.client_port : int = 0
        self.data_len : int = 0
        self.data : bytes = b''
        if head:
            import struct
            self.op, ip1, ip2, ip3, ip4, self.client_port, self.data_len = struct.unpack('!BBBBBHI', head)
            self.client_ip = '%d.%d.%d.%d' % (ip1, ip2, ip3, ip4)

    def toBytes(self) -> bytes:
        import struct
        ip_part = self.client_ip.split('.')
        return struct.pack('!BBBBBHI', self.op, int(ip_part[0]), int(ip_part[1]), int(ip_part[2]), int(ip_part[3]), self.client_port, len(self.data)) + self.data

    def __repr__(self):
        return '[op=%d, ip=%s, port=%d, data_len=%d]' % (self.op, self.client_ip, self.client_port, len(self.data))

import socket
import ssl
import threading

PROTOCOL_TCP = 0
PROTOCOL_UDP = 1

PACKET_SIZE = len(Packet().toBytes())

TCP_DATA_SIZE = 8192
UDP_DATA_SIZE = 65507

BLOCK_TIMEOUT = 1
PINGPONG_TIME = 30
UDP_TIMEOUT = 120

def recvPacket(conn : socket.socket) -> Packet:
    try:
        head = conn.recv(PACKET_SIZE)
    except:
        return None
    if not head:
        return None
    while len(head) < PACKET_SIZE:
        head += conn.recv(PACKET_SIZE - len(head))
    packet = Packet(head)
    if packet.data_len > 0:
        data = conn.recv(packet.data_len)
        if not data:
            return None
        while len(data) < packet.data_len:
            data += conn.recv(packet.data_len - len(data))
        packet.data = data
    return packet

class NATTunnelServer(threading.Thread):

    class __VirtualServer(threading.Thread):

        def __init__(self, conn : socket.socket):
            super().__init__(name='Virtual Server')
            self.source = conn
            self.socks = [conn]
            self.target = None
            self.protoType = -1
            self.shouldStop = False

        def stop(self):
            self.shouldStop = True

        def run(self):
            try:
                self.__run()
            finally:
                for s in self.socks:
                    s.close()

        def __run(self):
            import select
            import time
            begin = time.time()

            def findConn(addr : str, port : int) -> socket.socket:
                for sock in self.socks:
                    if sock is self.source or sock is self.target:
                        continue
                    peer = sock.getpeername()
                    if peer[0] == addr and peer[1] == port:
                        return sock
                return None

            while not getattr(self.source, '_closed') and not self.shouldStop:
                readable, writable, exceptional = select.select(self.socks, [], self.socks, BLOCK_TIMEOUT)
                sock : socket.socket
                for sock in readable:
                    if sock is self.source:
                        packet = recvPacket(self.source)
                        # print('RECV')
                        # print(packet)
                        if not packet:
                            print('[Server] NATTunnelClient %s Disconnected' % str(self.source.getpeername()))
                            self.source.close()
                            break

                        if packet.op == Packet.OP_BIND_TCP:
                            self.protoType = PROTOCOL_TCP
                            self.target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            self.target.bind(('0.0.0.0', packet.client_port))
                            self.setName('Virtual Server TCP:%d' % packet.client_port)
                            self.target.listen()
                            self.socks.append(self.target)
                            print('[Server] NATTunnelClient %s Bind TCP Port %d' % (str(self.source.getpeername()), packet.client_port))

                        elif packet.op == Packet.OP_BIND_UDP:
                            self.protoType = PROTOCOL_UDP
                            self.target = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            self.target.bind(('0.0.0.0', packet.client_port))
                            self.setName('Virtual Server UDP:%d' % packet.client_port)
                            self.socks.append(self.target)
                            print('[Server] NATTunnelClient %s Bind UDP Port %d' % (str(self.source.getpeername()), packet.client_port))

                        elif packet.op == Packet.OP_CLIENT_SEND:
                            if self.protoType == PROTOCOL_TCP:
                                client = findConn(packet.client_ip, packet.client_port)
                                if client:
                                    client.sendall(packet.data)
                            elif self.protoType == PROTOCOL_UDP:
                                self.target.sendto(packet.data, (packet.client_ip, packet.client_port))
                            else:
                                raise Exception('No Listener.')

                        elif packet.op == Packet.OP_CLIENT_DISCONN:
                            client = findConn(packet.client_ip, packet.client_port)
                            if client:
                                self.socks.remove(client)
                                print('[Server] TCP Connection %s Disconnected By Client' % str(client.getpeername()))
                                client.close()

                        elif packet.op == Packet.OP_PING:
                            packet = Packet()
                            packet.op = Packet.OP_PONG
                            self.source.sendall(packet.toBytes())
                        
                        else:
                            raise Exception('Packet Error')
                    elif sock is self.target:
                        if self.protoType == PROTOCOL_TCP:
                            conn, addr = self.target.accept()
                            self.socks.append(conn)
                            print('[Server] New Connection %s Connect to Port %d' % (str(conn.getpeername()), self.target.getsockname()[1]))
                            packet = Packet()
                            packet.op = Packet.OP_CLIENT_CONN
                            packet.client_ip, packet.client_port = conn.getpeername()
                            
                            # print('SEND')
                            # print(packet)
                            
                            self.source.sendall(packet.toBytes())
                        else:
                            data, addr = self.target.recvfrom(UDP_DATA_SIZE)
                            packet = Packet()
                            packet.op = Packet.OP_CLIENT_SEND
                            packet.client_ip, packet.client_port = addr
                            packet.data = data

                            # print('SEND')
                            # print(packet)

                            self.source.sendall(packet.toBytes())
                    else:
                        try:
                            data = sock.recv(TCP_DATA_SIZE)
                        except:
                            if not sock in exceptional:
                                exceptional.append(sock)
                            continue
                        if data:
                            packet = Packet()
                            packet.op = Packet.OP_CLIENT_SEND
                            packet.client_ip, packet.client_port = sock.getpeername()
                            packet.data = data

                            # print('SEND')
                            # print(packet)

                            self.source.sendall(packet.toBytes())
                        else:
                            self.socks.remove(sock)
                            print('[Server] TCP Connection %s Disconnected By User' % str(sock.getpeername()))
                            packet = Packet()
                            packet.op = Packet.OP_CLIENT_DISCONN
                            packet.client_ip, packet.client_port = sock.getpeername()
                            sock.close()

                            # print('SEND')
                            # print(packet)

                            self.source.sendall(packet.toBytes())
                for sock in exceptional:
                    print('Exception on: %s' % str(sock))
                    if sock is self.source or sock is self.target:
                        print('[Server] NATTunnelClient %s Disconnected' % str(sock.getpeername()))
                        self.source.close()
                    else:
                        self.socks.remove(sock)
                        print('[Server] TCP Connection %s Disconnected By Error' % str(sock.getpeername()))
                        packet = Packet()
                        packet.op = Packet.OP_CLIENT_DISCONN
                        packet.client_ip, packet.client_port = sock.getpeername()
                        sock.close()

                        # print('SEND')
                        # print(packet)

                        self.source.sendall(packet.toBytes())

                if not getattr(self.source, '_closed') and not self.target and time.time() - begin > BLOCK_TIMEOUT: # First Packet Timeout
                    self.source.close()

            for s in self.socks:
                s.close()

    def __init__(self, port : int = 2345, cert : str = None, key : str = None):
        super().__init__(name='NATTunnel Server Thread')
        self.shouldStop = False
        self.vslist = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(('0.0.0.0', port))
        self.sock.listen()
        if cert:
            self.sock = ssl.wrap_socket(self.sock, keyfile = key, certfile = cert, server_side = True, ssl_version=ssl.PROTOCOL_TLSv1_2)
    
    def stop(self):
        self.shouldStop = True

    def run(self):
        self.sock.settimeout(BLOCK_TIMEOUT)
        while not self.shouldStop:
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except ssl.SSLError:
                print('It seems that someone forgot to turn on SSL.')
                continue
            vs = NATTunnelServer.__VirtualServer(conn)
            self.vslist.append(vs)
            vs.start()
        for vs in self.vslist:
            vs.stop()
        self.sock.close()

class NATTunnelClient(threading.Thread):

    def __init__(self, server_addr : str, localaddr : tuple, remoteport : int, server_port : int = 2345, protocol : int = PROTOCOL_TCP, use_ssl : bool = False, ca : str = None):
        super().__init__(name='NATTunnel Client Thread')
        self.localaddr = localaddr
        self.remoteport = remoteport
        self.protocol = protocol
        if self.protocol != PROTOCOL_TCP and self.protocol != PROTOCOL_UDP:
            raise Exception('No such protocol: %d' % protocol)
        self.shouldStop = False

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((server_addr, server_port))
        if use_ssl:
            self.sock = ssl.wrap_socket(self.sock, ssl_version=ssl.PROTOCOL_TLSv1_2, ca_certs=ca)
        
        self.socks = [self.sock]
        
        packet = Packet()
        packet.client_port = self.remoteport
        if self.protocol == PROTOCOL_TCP:
            packet.op = Packet.OP_BIND_TCP
        elif self.protocol == PROTOCOL_UDP:
            packet.op = Packet.OP_BIND_UDP

        # print('SEND')
        # print(packet)

        self.sock.sendall(packet.toBytes())
        print('[Client] Local Port %s forward to %s' % (str(self.localaddr), str((server_addr, remoteport))))

    def stop(self):
        self.shouldStop = True

    def run(self):
        try:
            self.__run()
        finally:
            for s in self.socks:
                s.close()

    def __run(self):
        import select
        import time

        virtual_clients = {}
        udp_lastaccess = {}

        def getRemoteAddr(conn : socket.socket) -> tuple:
            for i in virtual_clients:
                if conn is virtual_clients[i]:
                    strs = i.split(':')
                    return (strs[0], int(strs[1]))
            return None
        
        lastaccess = time.time()
        while not getattr(self.sock, '_closed') and not self.shouldStop:
            readable, writable, exceptional = select.select(self.socks, [], self.socks, BLOCK_TIMEOUT)
            if not readable and not exceptional and time.time() - lastaccess > PINGPONG_TIME:
                packet = Packet()
                packet.op = Packet.OP_PING
                self.sock.sendall(packet.toBytes())
                lastaccess = time.time()

            sock : socket.socket
            for sock in readable:
                if sock is self.sock:
                    packet = recvPacket(sock)
                    # print('RECV')
                    # print(packet)
                    if not packet:
                        print('[Client] Lost server connection')
                        sock.close()
                        break
                    
                    key = '%s:%d' % (packet.client_ip, packet.client_port)
                    if packet.op == Packet.OP_CLIENT_CONN:
                        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        try:
                            client.connect(self.localaddr)
                        except:
                            packet.op = Packet.OP_CLIENT_DISCONN
                            self.sock.sendall(packet.toBytes())
                            continue
                        self.socks.append(client)
                        print('[Client] New TCP Connection %s as %s' % (str(client.getsockname()), key))
                        virtual_clients[key] = client
                    elif packet.op == Packet.OP_CLIENT_SEND:
                        if self.protocol == PROTOCOL_TCP:
                            if not key in virtual_clients:
                                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                try:
                                    client.connect(self.localaddr)
                                except:
                                    packet.op = Packet.OP_CLIENT_DISCONN
                                    packet.data = b''
                                    self.sock.sendall(packet.toBytes())
                                    continue
                                self.socks.append(client)
                                print('[Client] New TCP Connection %s as %s' % (str(client.getsockname()), key))
                                virtual_clients[key] = client

                            client = virtual_clients[key]
                            client.sendall(packet.data)
                        else:
                            first = False
                            if not key in virtual_clients:
                                first = True
                                client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                self.socks.append(client)
                                virtual_clients[key] = client
                            

                            client = virtual_clients[key]
                            udp_lastaccess[key] = time.time()
                            client.sendto(packet.data, self.localaddr)
                            if first:
                                print('[Client] New UDP Connection %s as %s' % (str(client.getsockname()), key))
                    elif packet.op == Packet.OP_CLIENT_DISCONN:
                        if key in virtual_clients:
                            client = virtual_clients[key]
                            print('[Client] TCP Connection %s as %s Disconnected By Remote' % (str(client.getsockname()), key))
                            client.close()
                            self.socks.remove(client)
                            del virtual_clients[key]
                    elif packet.op == Packet.OP_PONG:
                        # print('PONG')
                        pass
                    else:
                        raise Exception('Packet Error')

                else:
                    packet = Packet()
                    packet.client_ip, packet.client_port = getRemoteAddr(sock)
                    key = '%s:%d' % (packet.client_ip, packet.client_port)
                    if self.protocol == PROTOCOL_TCP:
                        try:
                            data = sock.recv(TCP_DATA_SIZE)
                        except:
                            if not sock in exceptional:
                                exceptional.append(sock)
                            continue
                        if data:
                            packet.op = Packet.OP_CLIENT_SEND
                            packet.data = data
                        else:
                            packet.op = Packet.OP_CLIENT_DISCONN
                            self.socks.remove(sock)
                            print('[Client] TCP Connection %s as %s Disconnected By Local' % (str(sock.getsockname()), key))
                            del virtual_clients[key]
                            sock.close()
                    else:
                        udp_lastaccess[key] = time.time()
                        data, addr = sock.recvfrom(UDP_DATA_SIZE)
                        packet.op = Packet.OP_CLIENT_SEND
                        packet.data = data
                    
                    # print('SEND')
                    # print(packet)

                    self.sock.sendall(packet.toBytes())
                    lastaccess = time.time()
            
            for sock in exceptional:
                print('Exception on: %s' % str(sock))
                if sock is not self.sock:
                    packet = Packet()
                    packet.client_ip, packet.client_port = getRemoteAddr(sock)
                    key = '%s:%d' % (packet.client_ip, packet.client_port)
                    packet.op = Packet.OP_CLIENT_DISCONN
                    del virtual_clients[key]
                    print('[Client] TCP Connection %s as %s Disconnected By Error' % (str(sock.getsockname()), key))

                    # print('SEND')
                    # print(packet)

                    self.sock.sendall(packet.toBytes())
                    lastaccess = time.time()
                else:
                    print('[Client] Lost server connection')
                self.socks.remove(sock)
                sock.close()

            if self.protocol == PROTOCOL_UDP:
                c = []
                t = time.time()
                for s in self.socks:
                    if s is not self.sock:
                        cip, cport = getRemoteAddr(s)
                        key = '%s:%d' % (cip, cport)
                        if t - udp_lastaccess[key] > UDP_TIMEOUT:
                            c.append(s)
                for s in c:
                    self.socks.remove(s)
                    cip, cport = getRemoteAddr(s)
                    key = '%s:%d' % (cip, cport)
                    del virtual_clients[key]
                    del udp_lastaccess[key]
                    print('[Client] UDP Socket %s as %s Timeout, Closed' % (str(s.getsockname()), key))
                    s.close()
            
        for s in self.socks:
            s.close()

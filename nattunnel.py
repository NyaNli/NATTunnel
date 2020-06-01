from threading import Thread
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR
from ssl import wrap_socket, PROTOCOL_TLSv1_2
from struct import pack, unpack
from select import select
from time import sleep, time

class SocketError(RuntimeError):
    def __init__(self, conn, ex):
        self.conn = conn
        self.ex = ex

# Full Packet:
# | 'NATT' | Sub Packet Size (4 Bytes) | Sub Packet |
# Sub Packet:
# | Operate (1 Byte) | Port (2 Bytes) | Hostname String Length (2 Bytes) | Hostname String | Data |
class Packet:

    MAGIC_NUM = b'NATT'
    MAGIC_TLS = b'\x16\x03'

    OP_SOCKET_CLOSED = 0
    OP_BIND_TCP = 1
    OP_BIND_UDP = 2
    OP_USER_CONN = 3
    OP_USER_MSG = 4
    OP_USER_DISCONN = 5
    OP_ERROR = 6
    OP_PING = 7
    OP_PONG = 8

    def __init__(self, conn : socket = None):
        def recvAll(size) -> bytes:
            if size == 0:
                return b''
            data = b''
            if size > 0:
                while len(data) < size:
                    d = conn.recv(size - len(data))
                    if not d:
                        return None
                    data += d
            return data

        self.op = Packet.OP_SOCKET_CLOSED
        self.host = '0.0.0.0'
        self.port = 0
        self.data = b''

        if conn:
            magic = recvAll(4)
            if not magic:
                return
            if magic != Packet.MAGIC_NUM:
                if magic[:2] == Packet.MAGIC_TLS:
                    return
                raise RuntimeError('Wrong Packet.')
            datasize = recvAll(4)
            if not datasize:
                return
            data = recvAll(*unpack('!I', datasize))
            if not data:
                return
            self._resolvePacket(data)

    def send(self, conn : socket):
        packet = self._buildPacket()
        packet = Packet.MAGIC_NUM + pack('!I', len(packet)) + packet
        try:
            conn.sendall(packet)
        except Exception as ex:
            raise SocketError(conn, ex)

    def _buildPacket(self) -> bytes:
        if DEBUG_MODE:
            print('Send [op=%d, host=%s, port=%d, data_len=%d]' % (self.op,self.host,self.port,len(self.data)))
        bhost = self.host.encode('utf-8')
        return pack('!BHH', self.op, self.port, len(bhost)) + bhost + self.data

    def _resolvePacket(self, data: bytes):
        self.op, self.port, host_len = unpack('!BHH', data[:5])
        self.host = data[5 : 5 + host_len].decode('utf-8')
        self.data = data[5 + host_len :]
        if DEBUG_MODE:
            print('Recv [op=%d, host=%s, port=%d, data_len=%d]' % (self.op,self.host,self.port,len(self.data)))

TCP_RECV_BUFF = 8192
UDP_RECV_BUFF = 65507
UDP_IDLE_TIMEOUT = 120
HEARTBEAT_TIME = 30
SHOW_ERR_LOG = False
DEBUG_MODE = False

class AbstractTunnel(Thread):
    def __init__(self, conn : socket, server_side : bool = False):
        super().__init__(target=self.__run)
        self.__server_side = server_side
        self.__socket = conn
        self.__sockets = [conn]
        self.__should_stop = False
        self.__timeout = 1

        self.__switchTree = {}
        self.__switchTree[Packet.OP_SOCKET_CLOSED] = self.__onSocketClosed
        self.__switchTree[Packet.OP_BIND_TCP] = self._onBindTcp
        self.__switchTree[Packet.OP_BIND_UDP] = self._onBindUdp
        self.__switchTree[Packet.OP_USER_CONN] = self._onUserConnect
        self.__switchTree[Packet.OP_USER_MSG] = self._onUserMsg
        self.__switchTree[Packet.OP_USER_DISCONN] = self._onUserDisconnect
        self.__switchTree[Packet.OP_ERROR] = self._onErrorMsg
        self.__switchTree[Packet.OP_PING] = self._onPing
        self.__switchTree[Packet.OP_PONG] = self._onPong

# Private =====================================================================

    def __run(self):
        try:
            self._onStart()
        except Exception as ex:
            self._err(self.__socket, ex)
            self.__should_stop = True

        while not self.__should_stop:
            readable, _, closeable = select(self.__sockets, [], self.__sockets, self.__timeout)
            if not readable and not closeable:
                try:
                    self._onIdle()
                except Exception as ex:
                    self._err(self.__socket, ex)
                    self.__should_stop = True
            if self.__server_side:
                self.__serverRun(readable, closeable)
            else:
                self.__clientRun(readable, closeable)

        try:
            self._onStop()
        except Exception as ex:
            self._err(self.__socket, ex)
        for s in self.__sockets:
            s.close()

    def __serverRun(self, readable, closeable):
        for s in readable:
            if s is self.__socket:
                try:
                    conn, _ = s.accept()
                except Exception as ex:
                    self._err(s, ex)
                    continue
                self._addSocket(conn)
            else:
                try:
                    packet = Packet(s)
                    self.__switchTree[packet.op](s, packet)
                except SocketError as ex:
                    self._err(ex.conn, ex.ex)
                    if ex.conn not in closeable:
                        closeable.append(s)
                except Exception as ex:
                    self._err(s, ex)
                    if s not in closeable:
                        closeable.append(s)
        for s in closeable:
            self.__onSocketClosed(s)

    def __clientRun(self, readable, closeable):
        for s in readable:
            try:
                if s is self.__socket:
                    packet = Packet(s)
                    self.__switchTree[packet.op](s, packet)
                else:
                    self._onUnknownReadable(s)
            except SocketError as ex:
                self._err(ex.conn, ex.ex)
                if ex.conn in self.__sockets and ex.conn not in closeable:
                    closeable.append(ex.conn)
            except Exception as ex:
                self._err(s, ex)
                if s not in closeable:
                    closeable.append(s)
        for s in closeable:
            self.__onSocketClosed(s)

    def __onSocketClosed(self, conn : socket, packet : Packet = None):
        if conn is self.__socket:
            self.__should_stop = True
        else:
            if not self.__server_side:
                try:
                    self._onUnknownError(conn)
                except:
                    pass
            self._removeSocket(conn)
            conn.close()

# Private =====================================================================

# Protected ===================================================================

    def _err(self, conn, ex):
        if SHOW_ERR_LOG:
            print('# ==================================')
            print('Thread: %s' % self.getName())
            print(conn)
            if DEBUG_MODE:
                import traceback
                traceback.print_exc()
            else:
                print('[%s] %s' % (ex.__class__.__name__, ex))
            print('# ==================================')

        receiver = None
        if self.__server_side:
            if conn is not self.__socket:
                receiver = conn
        elif conn is self.__socket:
            receiver = self.__socket
        if receiver:
            try:
                packet = Packet()
                packet.op = Packet.OP_ERROR
                packet.data = ('[%s] %s' % (ex.__class__.__name__, ex)).encode('utf-8')
                packet.send(receiver)
            except:
                pass

    def _addSocket(self, conn : socket):
        if conn not in self.__sockets:
            self.__sockets.append(conn)

    def _removeSocket(self, conn : socket):
        if conn in self.__sockets:
            self.__sockets.remove(conn)

# Protected ===================================================================

# Public ======================================================================

    def stop(self):
        self.__should_stop = True
    
    def setTimeout(self, timeout : int):
        self.__timeout = timeout

# Public ======================================================================

# Abstract ====================================================================

    def _onStart(self):
        pass

    def _onStop(self):
        pass

    def _onIdle(self):
        pass

    def _onBindTcp(self, conn : socket, packet : Packet):
        raise NotImplementedError('Do not support this operate: %d' % packet.op)

    def _onBindUdp(self, conn : socket, packet : Packet):
        raise NotImplementedError('Do not support this operate: %d' % packet.op)

    def _onUserConnect(self, conn : socket, packet : Packet):
        raise NotImplementedError('Do not support this operate: %d' % packet.op)

    def _onUserMsg(self, conn : socket, packet : Packet):
        raise NotImplementedError('Do not support this operate: %d' % packet.op)

    def _onUserDisconnect(self, conn : socket, packet : Packet):
        raise NotImplementedError('Do not support this operate: %d' % packet.op)

    def _onErrorMsg(self, conn : socket, packet : Packet):
        raise NotImplementedError('Do not support this operate: %d' % packet.op)

    def _onPing(self, conn : socket, packet : Packet):
        raise NotImplementedError('Do not support this operate: %d' % packet.op)

    def _onPong(self, conn : socket, packet : Packet):
        raise NotImplementedError('Do not support this operate: %d' % packet.op)

    def _onUnknownReadable(self, conn : socket):
        raise NotImplementedError

    def _onUnknownError(self, conn : socket):
        raise NotImplementedError

# Abstract ====================================================================

# Server ======================================================================

class TCPVirtualServer(AbstractTunnel):
    def __init__(self, conn : socket, port : int):
        super().__init__(conn)
        self.setName('Virtual Server TCP:%s' % port)
        self.__source = conn
        self.__target = socket(AF_INET, SOCK_STREAM)
        self.__target.bind(('0.0.0.0', port))
        self.__clients = {}

    def _onStart(self):
        self.__target.listen()
        self._addSocket(self.__target)
        print('[Server] Client %s bind to port TCP:%d' % (self.__source.getpeername(), self.__target.getsockname()[1]))

    def _onStop(self):
        print('[Server] Port TCP:%d closed.' % self.__target.getsockname()[1])

    def _onUserMsg(self, conn : socket, packet : Packet):
        key = str((packet.host, packet.port))
        if key in self.__clients:
            target = self.__clients[key]
            try:
                target.sendall(packet.data)
            except Exception as ex:
                raise SocketError(target, ex)
        else:
            packet.op = Packet.OP_USER_DISCONN
            packet.data = b''
            packet.send(conn)

    def _onUserDisconnect(self, conn : socket, packet : Packet):
        key = str((packet.host, packet.port))
        if key in self.__clients:
            target = self.__clients[key]
            self._removeSocket(target)
            del self.__clients[key]
            target.close()
        elif DEBUG_MODE:
            print('Unknown connection %s' % key)

    def _onErrorMsg(self, conn : socket, packet : Packet):
        pass

    def _onPing(self, conn : socket, packet : Packet):
        packet = Packet()
        packet.op = Packet.OP_PONG
        packet.send(conn)

    def _onUnknownReadable(self, conn : socket):
        if conn is self.__target:
            try:
                nconn, addr = conn.accept()
                self.__clients[str(addr)] = nconn
                self._addSocket(nconn)
            except Exception as ex:
                self._err(conn, ex)
                return
            packet = Packet()
            packet.op = Packet.OP_USER_CONN
            packet.host, packet.port = addr
            packet.send(self.__source)
        else:
            data = conn.recv(TCP_RECV_BUFF)
            packet = Packet()
            packet.host, packet.port = conn.getpeername()
            if data:
                packet.op = Packet.OP_USER_MSG
                packet.data = data
            else:
                packet.op = Packet.OP_USER_DISCONN
                del self.__clients[str(conn.getpeername())]
                self._removeSocket(conn)
            packet.send(self.__source)

    def _onUnknownError(self, conn : socket):
        packet = Packet()
        packet.op = Packet.OP_USER_DISCONN
        packet.host, packet.port = conn.getpeername()
        packet.send(self.__source)

class UDPVirtualServer(AbstractTunnel):
    def __init__(self, conn : socket, port : int):
        super().__init__(conn)
        self.setName('Virtual Server UDP:%s' % port)
        self.__source = conn
        self.__port = port
        self.__target = socket(AF_INET, SOCK_DGRAM)
        self.__target.bind(('0.0.0.0', port))

    def _onStart(self):
        self._addSocket(self.__target)
        print('[Server] Client %s bind to port UDP:%d' % (self.__source.getpeername(), self.__target.getsockname()[1]))

    def _onStop(self):
        print('[Server] Port UDP:%d closed.' % self.__target.getsockname()[1])

    def _onUserMsg(self, conn : socket, packet : Packet):
        addr = (packet.host, packet.port)
        self.__target.sendto(packet.data, addr)

    def _onErrorMsg(self, conn : socket, packet : Packet):
        pass

    def _onPing(self, conn : socket, packet : Packet):
        packet = Packet()
        packet.op = Packet.OP_PONG
        packet.send(conn)

    def _onUnknownReadable(self, conn : socket):
        data, addr = conn.recvfrom(UDP_RECV_BUFF)
        packet = Packet()
        packet.op = Packet.OP_USER_MSG
        packet.host, packet.port = addr
        packet.data = data
        packet.send(self.__source)

    def _onUnknownError(self, conn : socket):
        pass

class NATTunnelServer(AbstractTunnel):
    def __init__(self, port : int = 12345, cert_file : str = None, key_file : str = None):
        self.__vslist = {}
        self.__server = socket(AF_INET, SOCK_STREAM)
        self.__server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.__server.bind(('0.0.0.0', port))
        if cert_file:
            self.__server = wrap_socket(self.__server, keyfile = key_file, certfile = cert_file, server_side = True, ssl_version=PROTOCOL_TLSv1_2)
        super().__init__(self.__server, True)
        self.setName('NAT Tunnel Server')

    def _onStart(self):
        self.__server.listen()
        print('NAT Tunnel Server Started. Port: %s' % self.__server.getsockname()[1])

    def _onStop(self):
        print('NAT Tunnel Server Closing...')
        for port in self.__vslist:
            if self.__vslist[port].isAlive():
                self.__vslist[port].stop()

    def __createVirtualServer(self, conn, port, clazz):
        if port in self.__vslist and self.__vslist[port].isAlive():
            raise RuntimeError('Port %d already in use.' % port)
        vs = clazz(conn, port)
        vs.start()
        self._removeSocket(conn)
        self.__vslist[port] = vs

    def _onBindTcp(self, conn : socket, packet : Packet):
        self.__createVirtualServer(conn, packet.port, TCPVirtualServer)
    
    def _onBindUdp(self, conn : socket, packet : Packet):
        self.__createVirtualServer(conn, packet.port, UDPVirtualServer)

# Server ======================================================================

# Client ======================================================================

class NATTunnelTCPClient(AbstractTunnel):
    def __init__(self, server_addr : str, local_addr : tuple, remote_port : int, server_port : int = 12345):
        self.__local_addr = local_addr
        remote = socket(AF_INET, SOCK_STREAM)
        remote.connect((server_addr, server_port))
        try:
            remote = wrap_socket(remote, ssl_version=PROTOCOL_TLSv1_2)
        except:
            remote = socket(AF_INET, SOCK_STREAM)
            remote.connect((server_addr, server_port))
        self.__remote = remote
        super().__init__(remote)
        self.__local_addr = local_addr
        self.__remote_port = remote_port
        self.__clients = {}
        self.__lastaccess = None
        self.setName('NAT Tunnel Client TCP:%s' % remote_port)

    def _onStart(self):
        packet = Packet()
        packet.op = Packet.OP_BIND_TCP
        packet.port = self.__remote_port
        packet.send(self.__remote)
        self.__lastaccess = time()
        print('NAT Tunnel Client Forward TCP:%s:%d to TCP:%s:%d' % (self.__local_addr[0], self.__local_addr[1], self.__remote.getpeername()[0], self.__remote_port))

    def _onStop(self):
        print('NAT Tunnel Client TCP:%d Stopped' % self.__remote_port)

    def _onIdle(self):
        if time() - self.__lastaccess > HEARTBEAT_TIME:
            packet = Packet()
            packet.op = Packet.OP_PING
            packet.send(self.__remote)
            self.__lastaccess = time()

    def _onUserConnect(self, conn : socket, packet : Packet):
        self.__lastaccess = time()

        key = (packet.host, packet.port)
        client = socket(AF_INET, SOCK_STREAM)
        self._addSocket(client)
        self.__clients[str(key)] = client
        try:
            client.connect(self.__local_addr)
        except Exception as ex:
            self._err(client, ex)
            raise SocketError(client, ex)
        print('[TCPClient:%d] New TCP Connection %s as %s' % (self.__remote_port, client.getsockname(), key))

    def _onUserMsg(self, conn : socket, packet : Packet):
        self.__lastaccess = time()

        key = str((packet.host, packet.port))
        if key in self.__clients:
            client = self.__clients[key]
            try:
                client.sendall(packet.data)
            except Exception as ex:
                self._err(client, ex)
                raise SocketError(client, ex)
        else:
            packet.op = Packet.OP_USER_DISCONN
            packet.data = b''
            packet.send(conn)

    def _onUserDisconnect(self, conn : socket, packet : Packet):
        self.__lastaccess = time()

        key = str((packet.host, packet.port))
        if key in self.__clients:
            client = self.__clients[key]
            print('[TCPClient:%d] TCP Connection %s as %s disconnected by remote.' % (self.__remote_port, client.getsockname(), key))
            client.close()
            del self.__clients[key]
            self._removeSocket(client)
        elif DEBUG_MODE:
            print('Unknown connection %s' % key)

    def _onErrorMsg(self, conn : socket, packet : Packet):
        print('[TCPClient:%d] Server Error: %s' % (self.__remote_port, packet.data.decode('utf-8')))

    def _onPong(self, conn : socket, packet : Packet):
        pass

    def _onUnknownReadable(self, conn : socket):
        packet = Packet()
        key = None
        for k in self.__clients:
            if conn is self.__clients[k]:
                key = k
                break
        if key:
            packet.host, packet.port = eval(key)
        else:
            raise Exception('Cannot find target client.')
        data = conn.recv(TCP_RECV_BUFF)
        if data:
            packet.op = Packet.OP_USER_MSG
            packet.data = data
        else:
            packet.op = Packet.OP_USER_DISCONN
            print('[TCPClient:%d] TCP Connection %s as %s disconnected by local.' % (self.__remote_port, conn.getsockname(), key))
            self._removeSocket(conn)
            del self.__clients[key]
            conn.close()
        packet.send(self.__remote)
        self.__lastaccess = time()

    def _onUnknownError(self, conn : socket):
        key = None
        for k in self.__clients:
            if conn is self.__clients[k]:
                key = k
                break
        if key:
            packet = Packet()
            packet.op = Packet.OP_USER_DISCONN
            packet.host, packet.port = eval(key)
            packet.send(self.__remote)
            self.__lastaccess = time()
            del self.__clients[key]
            print('[TCPClient:%d] TCP Connection %s as %s disconnected by local.' % (self.__remote_port, conn.getsockname(), key))

class NATTunnelUDPClient(AbstractTunnel):
    def __init__(self, server_addr : str, local_addr : tuple, remote_port : int, server_port : int = 12345):
        self.__local_addr = local_addr
        remote = socket(AF_INET, SOCK_STREAM)
        remote.connect((server_addr, server_port))
        try:
            remote = wrap_socket(remote, ssl_version=PROTOCOL_TLSv1_2)
        except:
            remote = socket(AF_INET, SOCK_STREAM)
            remote.connect((server_addr, server_port))
        self.__remote = remote
        super().__init__(remote)
        self.__local_addr = local_addr
        self.__remote_port = remote_port
        self.__clients = {}
        self.__lastaccess = {}
        self.setName('NAT Tunnel Client UDP:%s' % remote_port)

    def _onStart(self):
        packet = Packet()
        packet.op = Packet.OP_BIND_UDP
        packet.port = self.__remote_port
        packet.send(self.__remote)
        self.__lastaccess['remote'] = time()
        print('NAT Tunnel Client Forward UDP:%s:%d to UDP:%s:%d' % (self.__local_addr[0], self.__local_addr[1], self.__remote.getpeername()[0], self.__remote_port))

    def _onStop(self):
        print('NAT Tunnel Client UDP:%d Stopped' % self.__remote_port)

    def _onIdle(self):
        delk = []
        for k in self.__clients:
            l = self.__lastaccess[k]
            if time() - l > UDP_IDLE_TIMEOUT:
                delk.append(k)
        for k in delk:
            print('[UDPClient:%d] UDP Connection %s as %s idle timeout expired.' % (self.__remote_port, self.__clients[k].getsockname(), k))
            self._removeSocket(self.__clients[k])
            self.__clients[k].close()
            del self.__clients[k]
            
        if time() - self.__lastaccess['remote'] > HEARTBEAT_TIME:
            packet = Packet()
            packet.op = Packet.OP_PING
            packet.send(self.__remote)
            self.__lastaccess['remote'] = time()

    def _onUserMsg(self, conn : socket, packet : Packet):
        self.__lastaccess['remote'] = time()
        key = str((packet.host, packet.port))
        first = False
        if key not in self.__clients:
            self.__clients[key] = socket(AF_INET, SOCK_DGRAM)
            self._addSocket(self.__clients[key])
            self.__lastaccess[key] = time()
            first = True
        client = self.__clients[key]
        client.sendto(packet.data, self.__local_addr)
        if first:
            print('[UDPClient:%d] New UDP Connection %s as %s' % (self.__remote_port, client.getsockname(), key))

    def _onErrorMsg(self, conn : socket, packet : Packet):
        print('[UDPClient:%d] Server Error: %s' % (self.__remote_port, packet.data.decode('utf-8')))

    def _onPong(self, conn : socket, packet : Packet):
        pass

    def _onUnknownReadable(self, conn : socket):
        data, _ = conn.recvfrom(UDP_RECV_BUFF)
        packet = Packet()
        packet.op = Packet.OP_USER_MSG
        key = None
        for k in self.__clients:
            if conn is self.__clients[k]:
                key = k
                break
        if key:
            self.__lastaccess[key] = time()
            packet.host, packet.port = eval(key)
            packet.data = data
            packet.send(self.__remote)
            self.__lastaccess['remote'] = time()
        else:
            raise Exception('Cannot find target client.')

    def _onUnknownError(self, conn : socket):
        pass

# Client ======================================================================

# Commandline =================================================================

if __name__ == "__main__":
    def main():
        from sys import argv

        THREADS = []

        def threadsAlive():
            alive = False
            for t in THREADS:
                alive = alive or t.isAlive()
            return alive

        def usage():
            print('Usage:')
            print(' NAT Tunnel Server')
            print('  nattunnel server [{--port|-p}=PORT] [{--cert_file|-cf}=CERT_FILE_PATH]')
            print('                   [{--key_file|-kf}=KEY_FILE_PATH]')
            print('  Example:')
            print('   nattunnel server')
            print('   nattunnel server --port=2377')
            print('   nattunnel server --port=1324 --cert_file=server.pem')
            print('   nattunnel server -p=2323 -cf=server.crt -kf=ca.key')
            print()
            print(' NAT Tunnel Client')
            print('  nattunnel client {--server|-s}=SERVER_ADDR[:SERVER_PORT]')
            print('                   {--conf|-c}={TCP|UDP}:LOCAL_ADDR:LOCAR_PORT:REMOTE_PORT')
            print('                   [{--conf|-c}=CONF2 [{--conf|-c}=CONF3 [...]]]')
            print('  Example:')
            print('   nattunnel client --server=example.com --conf=tcp:localhost:10343:25565')
            print('   nattunnel client --s=example.com:4579 -c:localhost:443:443 -c=udp:1.1.1.1:53:53')

        def client(server : tuple, conf : list):
            cl = []
            for c in conf:
                strs = c.lower().split(':')
                if len(strs) != 4 or strs[0] != 'tcp' and strs[0] != 'udp' or not strs[2].isnumeric() or not strs[3].isnumeric():
                    raise Exception('Wrong Conf %s' % c)
                cl.append([strs[0], strs[1], int(strs[2]), int(strs[3])])
            try:
                for c in cl:
                    client = None
                    if c[0] == 'tcp':
                        client = NATTunnelTCPClient(server[0], (c[1], c[2]), c[3], server[1])
                    else:
                        client = NATTunnelUDPClient(server[0], (c[1], c[2]), c[3], server[1])
                    THREADS.append(client)
                    client.start()
            except Exception as ex:
                print(ex)

        def server(port : int, cert_file : str, key_file : str):
            try:
                server = NATTunnelServer(port, cert_file, key_file)
                THREADS.append(server)
                server.start()
            except Exception as ex:
                print(ex)

        class ArgDict:
            def __init__(self, args, allow):
                self.__d = {}
                self.__allow = allow
                for arg in args:
                    strs = arg.split('=')
                    if len(strs) != 2:
                        continue
                    a = self.__getAllow(strs[0])
                    if a:
                        if a[0] not in self.__d:
                            self.__d[a[0]] = []
                        self.__d[a[0]].append(strs[1])

            def __getAllow(self, key):
                a = None
                for i in self.__allow:
                    if key in i:
                        a = i
                        break
                return a

            def __getitem__(self, index):
                if index not in self.__d:
                    return []
                else:   
                    return self.__d[index]

        args = argv[1:]
        if args:
            if args[0] == 'client':
                argd = ArgDict(args[1:], [['--server', '-s'], ['--conf', '-c']])
                if argd['--server'] and argd['--conf']:
                    addr = argd['--server'][0]
                    port = 12345
                    if ':' in addr:
                        try:
                            addr, port = addr.split(':')
                            port = int(port)
                        except:
                            print('Server Argument Error.')
                            usage()
                    try:
                        client((addr, port), argd['--conf'])
                    except Exception as ex:
                        print(ex)
                        usage()
                else:
                    usage()
            elif args[0] == 'server':
                argd = ArgDict(args[1:], [['--port', '-p'], ['--cert_file', '-cf'], ['--key_file', '-kf']])
                port = 12345
                cert_file = None
                key_file = None
                try:
                    if argd['--port']:
                        port = int(argd['--port'][0])
                except:
                    print('Port Argument Error.')
                    usage()
                if argd['--cert_file']:
                    cert_file = argd['--cert_file'][0]
                if argd['--key_file']:
                    key_file = argd['--key_file'][0]
                server(port, cert_file, key_file)
            else:
                usage()
        else:
            usage()
    
        try:
            while threadsAlive():
                sleep(1)
        except:
            for t in THREADS:
                t.stop()
    main()

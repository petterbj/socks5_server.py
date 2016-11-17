import socket
import struct
import sys
import select
import threading
import errno
def send_tcp_to_each_other(client_server_socket, server_remote_socket):
    while True:
        r, w, e = select.select([server_remote_socket,client_server_socket],[],[])
        if server_remote_socket in r:
            if client_server_socket.send(server_remote_socket.recv(4096)) <= 0:
                break
        if client_server_socket in r:
            if server_remote_socket.send(client_server_socket.recv(4096)) <= 0:
                break
def request_form_filler(data):
    form_pointer = 0
    socks_request = {}
    socks_request['VER'] = data[form_pointer]
    form_pointer += 1
    socks_request['CMD'] = data[form_pointer]
    form_pointer += 1
    socks_request['RSV'] = data[form_pointer]
    form_pointer += 1
    socks_request['ATYP'] = data[form_pointer]
    form_pointer += 1
    # IP V4 address: X'01'
    # DOMAINNAME: X'03'
    # IP V6 address: X'04'
    if socks_request['ATYP'] == b'\x01':
        socks_request['DST.ADDR'] = data[form_pointer:form_pointer+4]
        form_pointer += 4
    elif socks_request['ATYP'] == b'\x03':
        socks_request['DST.ADDR'] = data[form_pointer+1:form_pointer+1 +ord(data[form_pointer])]
        form_pointer += (1+ ord(data[form_pointer]))
    elif socks_request['ATYP'] == b'\x04':
        socks_request['DST.ADDR'] = data[form_pointer:form_pointer+16]
        form_pointer += 16
    else:
        print 'error'
    socks_request['DST.PORT'] = data[form_pointer:form_pointer+2]
    form_pointer += 2 
    request_form = socks_request
    return request_form

# X'00' NO AUTHENTICATION REQUIRED
def NO_AUTHENTICATION_REQUIRED(client_server_socket, client_addr_port):
    data = client_server_socket.recv(4096)
    socks_request = request_form_filler(data)

    # Analyzing the address type 
    # IP V4 address:    X'01'
    if socks_request['ATYP'] == b'\x01':
        remote_addr = socket.inet_ntoa(socks_request['DST.ADDR'])
    # DOMAINNAME:       X'03'
    elif socks_request['ATYP'] == b'\x03':
        remote_addr = socks_request['DST.ADDR']
    # IP V6 address:    X'04'
    # TODO ipv6 tocome
    # elif socks_request['ATYP'] == b'\x04':
    #     remote_addr = socket.inet_ntoa(socks_request['DST.ADDR'])
    else:
        # X'08' Address type not supported + ip address + port
        reply = b'\x05\x08\x00\x01' + '\x00\x00\x00\x00' + '\x00\x00'
        client_server_socket.send(reply)
        client_server_socket.close()
        print 'client_server_socket closed'
        return
    remote_port = int(struct.unpack('>H',(socks_request['DST.PORT']))[0])
    # VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT
    # CONNECT X'01'
    if socks_request['CMD'] == '\x01':
        server_remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print 'remote_addr, remote_port', remote_addr, remote_port
        try:
            server_remote_socket.connect((remote_addr,remote_port))
        except socket.error as e:
            print e
            if e.errno == errno.ENETUNREACH:
                reply = b'\x05\x03\x00\x01' + '\x00\x00\x00\x00' + '\x00\x00'
                client_server_socket.send(reply)
                client_server_socket.close()
                print 'client_server_socket closed'
                return
            elif e.errno == errno.EHOSTUNREACH:
                reply = b'\x05\x04\x00\x01' + '\x00\x00\x00\x00' + '\x00\x00'
                client_server_socket.send(reply)
                client_server_socket.close()
                print 'client_server_socket closed'
                return
            elif e.errno == errno.ECONNREFUSED:
                reply = b'\x05\x05\x00\x01' + '\x00\x00\x00\x00' + '\x00\x00'
                client_server_socket.send(reply)
                client_server_socket.close()
                print 'client_server_socket closed'
                return
            else:
                reply = b'\x05\x01\x00\x01' + '\x00\x00\x00\x00' + '\x00\x00'
                client_server_socket.send(reply)
                client_server_socket.close()
                print 'client_server_socket closed'
                return
 
        reply = b'\x05\x00\x00\x01'
        print server_remote_socket.getsockname()[0], server_remote_socket.getsockname()[1]
        reply += socket.inet_aton(server_remote_socket.getsockname()[0])
        reply += struct.pack('>H',server_remote_socket.getsockname()[1])
        
        client_server_socket.send(reply)
        try:
            send_tcp_to_each_other(client_server_socket, server_remote_socket)
        except socket.error as e:
            print e
            reply = b'\x05\x01\x00\x01' + '\x00\x00\x00\x00' + '\x00\x00'
            client_server_socket.send(reply)
        client_server_socket.close()
        print 'client_server_socket closed'
    # BIND X'02'
    # elif socks_request['CMD'] == '\x02':
    # TODO to be implemented
    # UDP ASSOCIATE X'03'
    # elif socks_request['CMD'] == '\x03':
    # TODO to be implemented
    else:
        # X'07' Command not supported + ip address + port
        reply = b'\x05\x07\x00\x01' + '\x00\x00\x00\x00' + '\x00\x00'
        client_server_socket.send(reply)
        client_server_socket.close()
        print 'client_server_socket closed'
def clientDealer(client_server_socket, client_addr_port):
    # [AUTHENTICATION METHOD NEGOTIATION START]
    data = client_server_socket.recv(4096)
    # print data.encode('hex')
    # X'00' NO AUTHENTICATION REQUIRED
    authentication_method = '\x00'
    client_server_socket.send(b'\x05\x00')
    # TODO more methods to come
    # [AUTHENTICATION METHOD NEGOTIATION END]
    
    # [METHOD-SPECIFIC SUB-NEGOTIATION START]
    if authentication_method == '\x00':
        NO_AUTHENTICATION_REQUIRED(client_server_socket,client_addr_port)
    # TODO other methods not supported yet
    # elif authentication_method == '\x01'
    #     # GSSAPI
    # elif authentication_method == '\x02' 
    #     # USERNAME/PASSWORD
    # else:
    #     # X'03' to X'7F' IANA ASSIGNED
    #     # X'80' to X'FE' RESERVED FOR PRIVATE METHODS
    #     # X'FF' NO ACCEPTABLE METHODS
    
if __name__ == "__main__":
    server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    # server_bind_address = ('localhost', 1082)
    server_bind_address = ('0.0.0.0', 1082)
    server_socket.bind(server_bind_address)
    server_socket.listen(15)
    try:
        while True:
            (client_server_socket, client_addr_port) = server_socket.accept()
            print 'socket accepted'
            thread = threading.Thread(target=clientDealer, args=(client_server_socket,client_addr_port))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print "Stopping"

import socket
import struct
import select
def send_tcp_to_each_other(client_server_socket, server_remote_socket):
    while True:
        r, w, e = select.select([server_remote_socket,client_server_socket],[],[])
        if server_remote_socket in r:
            if client_server_socket.send(server_remote_socket.recv(4096)) <= 0:break
        if client_server_socket in r:
            if server_remote_socket.send(client_server_socket.recv(4096)) <= 0:break
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

server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server_bind_address = ('localhost', 1082)
server_socket.bind(server_bind_address)
server_socket.listen(5)
while True:
    (client_server_socket, client_addr_port) = server_socket.accept()
    print 'socket accept'

    # method negotiate period
    data = client_server_socket.recv(4096)
    print data.encode('hex')
    # X'00' NO AUTHENTICATION REQUIRED
    client_server_socket.send(b'\x05\x00')

    # method dependent subnegotiate period
    data = client_server_socket.recv(4096)
    socks_request = request_form_filler(data)


    # Analyze the ip_addr and port
    if socks_request['ATYP'] == b'\x01':
        remote_addr = socket.inet_ntoa(socks_request['DST.ADDR'])
    elif socks_request['ATYP'] == b'\x03':
        remote_addr = socks_request['DST.ADDR']
    # elif socks_request['ATYP'] == b'\x04':
    #     remote_addr = socket.inet_ntoa(socks_request['DST.ADDR'])
    else:
        print 'error'
    remote_port = int(struct.unpack('>H',(socks_request['DST.PORT']))[0])


    if socks_request['CMD'] == '\x01':
        server_remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print remote_addr, remote_port
        server_remote_socket.connect((remote_addr,remote_port))
    elif socks_request['CMD'] == '\x02':
    elif socks_request['CMD'] == '\x03':
    else:

    # VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT
    reply = b'\x05\x00\x00\x01'
    print server_remote_socket.getsockname()[0], server_remote_socket.getsockname()[1]
    reply += socket.inet_aton(server_remote_socket.getsockname()[0])
    reply += struct.pack('>H',server_remote_socket.getsockname()[1])

    client_server_socket.send(reply)
    send_tcp_to_each_other(client_server_socketection, server_remote_socket)

    print 'client_server_socketection closed'
#server_socket.close()



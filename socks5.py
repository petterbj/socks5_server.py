import socket
import struct
import select
import time
server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
address = ('localhost', 1082)
server_socket.bind(address)
server_socket.listen(5)
while True:
    (conn, client_addr_port) = server_socket.accept()
    print 'socket accept'

    # method negotiate period
    data = conn.recv(4096)
    # X'00' NO AUTHENTICATION REQUIRED
    conn.send(b'\x05\x00')

    # method dependent subnegotiate period
    data = conn.recv(4096)

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
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print remote_addr, remote_port
        remote_socket.connect((remote_addr,remote_port))

    # VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT
    reply = b'\x05\x00\x00\x01'

    print remote_socket.getsockname()[0], remote_socket.getsockname()[1]

    reply += socket.inet_aton(remote_socket.getsockname()[0])
    reply += struct.pack('>H',remote_socket.getsockname()[1])
    conn.send(reply)

    while True:
        r, w, e = select.select([remote_socket,conn],[],[])
        if remote_socket in r:
            if conn.send(remote_socket.recv(4096)) <= 0:break
        if conn in r:
            if remote_socket.send(conn.recv(4096)) <= 0:break
    print 'connection closed'
#server_socket.close()



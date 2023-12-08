import socket
async def http(port, ip, tcp_or_udp):
    flag = True
    request = f"GET /api/data HTTP/1.1\r\nHost: {ip}\r\n\r\n"
    s = socket.socket(socket.AF_INET, tcp_or_udp)
    s.settimeout(1)
    try:
        s.connect((ip, port))
        s.sendall(request.encode())
        response = s.recv(4096)
    except socket.timeout:
        flag = False
    finally:
        s.close()
    return flag

async def echo(port, ip, tcp_or_udp):
    flag = True
    request = f"ECHO /api/echo HTTP/1.1\r\nHost: {ip}\r\n\r\n"
    s = socket.socket(socket.AF_INET, tcp_or_udp)
    s.settimeout(1)
    s.sendall(request.encode())
    try:
        s.connect((ip, port))
        s.sendall(request.encode())
        response = s.recv(4096)
    except socket.timeout:
        flag = False
    finally:
        s.close()
    return flag


async def dns(port, ip, tcp_or_udp):
    flag = False
    s = socket.socket(socket.AF_INET, tcp_or_udp)
    s.settimeout(1)
    query = b'\xAA\xAA\x01\x00\x00\x01\x00\x00' + b'\x00\x00\x00\x00' + b'\x07' + b'example' \
            + b'\x03' + b'com' + b'\x00' + b'\x00\x01' + b'\x00\x01'
    try:
        s.connect((ip, port))
        s.sendall(query)
        response = s.recv(1024)
    except socket.timeout:
        flag = False
    finally:
        s.close()
    return flag


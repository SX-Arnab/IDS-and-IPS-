import socket

srvr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srvr.bind(('', 1293))
srvr.listen(5)

while True:
    client, address = srvr.accept()
    client.send("Hello, Client!".encode())
    client.close()
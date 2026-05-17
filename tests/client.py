import socket
from struct import pack_into

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost', 12345))

message = client.recv(1024).decode()
print(message)

client.close()

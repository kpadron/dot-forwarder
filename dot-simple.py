#!/usr/bin/env python3
import socket, ssl
import struct, random


host = '127.0.0.1'
port = 5053
upstreams = ['1.1.1.1']
conns = []


def main():
	# Setup UDP server
	print('Starting UDP server listening on: %s#%d' % (host, port))
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind((host, port))

	# Connect to upstream servers
	for upstream in upstreams:
		print('Connecting to upstream server: %s' % (upstream))
		conns.append(upstream_connect(upstream, 853, 'cloudflare-dns.com'))

	# Serve forever
	try:
		while True:
			# Accept requests from a client
			data, addr = sock.recvfrom(4096)

			# Select upstream server to forward to
			index = random.randrange(len(conns))

			# Forward request to upstream server and get response
			data = upstream_forward(data, conns[index])

			# Send response to client
			sock.sendto(data, addr)
	except (KeyboardInterrupt, SystemExit):
		pass

	# Close upstream connections
	for conn in conns:
		upstream_close(conn)

	# Close UDP server
	sock.close()


def upstream_connect(host, port, server_name):
	"""
	Create an upstream connection to a server.

	Params:
		host        - host server to connect to
		port        - port on which to connect to host
		server_name - hostname to use for certificate verification

	Returns:
		A secure socket object
	"""

	context = ssl.create_default_context()

	# Create socket connection
	sock = socket.create_connection((host, port))
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
	sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1)
	sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 3)
	sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)

	# Wrap connection with SSL/TLS
	ssock = context.wrap_socket(sock, server_hostname=server_name)
	print(ssock.version())

	return ssock


def upstream_forward(data, ssock):
	"""
	Send a DNS request over TLS.

	Params:
		data  - normal DNS packet data to forward
		ssock - SSL/TLS socket connection to upstream DNS server

	Returns:
		A normal DNS response packet from upstream server

	Notes:
		Using DNS over TLS format as described here:
		https://tools.ietf.org/html/rfc7858
	"""

	# print('sending to upstream: %s' % (data))

	ssock.send(struct.pack('! H', len(data)) + data)

	data = ssock.recv(4096)
	# print('receiving from upstream: %s' % (data))

	return data[2:]


def upstream_close(ssock):
	"""
	Close an upstream connection.

	Params:
		ssock - secure socket object to close
	"""

	# Unwrap secure socket connection
	sock = ssock.unwrap()

	# Close underlying socket connection
	sock.close()


if __name__ == '__main__':
	main()

#!/usr/bin/env python3
import socket, ssl
import struct, random


listen_host = '127.0.0.1'
listen_port = 5053
upstreams = [('1.1.1.1', 853, 'cloudflare-dns.com')]
conns = []


def main():
	# Setup UDP server
	print('Starting UDP server listening on: %s#%d' % (listen_host, listen_port))
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind((listen_host, listen_port))

	# Connect to upstream servers
	for upstream in upstreams:
		conn = upstream_connect(*upstream)
		
		if conn is None:
			print('Failed to connect to upstream server: %s#%u' % (upstream[0], upstream[1]))
			continue
		
		print('Successfully connected to upstream server: %s#%u' % (upstream[0], upstream[1]))
		conns.append(conn)

	# Serve forever
	try:
		while True:
			# Accept requests from a client
			data, addr = sock.recvfrom(4096)

			# Select upstream server to forward to
			index = random.randrange(len(conns))

			# Forward request to upstream server and get response
			data = upstream_forward(conns[index], data)

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
	Establish a secure SSL/TLS connection to a upstream server.

	Params:
		host        - host server to connect to
		port        - port on which to connect to host
		server_name - hostname to use for certificate verification

	Returns:
		A connected socket object or None on failure
	"""

	try:
		# Create TCP socket
		sock = socket.socket()
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
		sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 3)
		sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

		# Wrap connection with SSL/TLS
		context = ssl.create_default_context()
		sock = context.wrap_socket(sock, server_hostname=server_name)

		# Connect to upstream server
		sock.connect((host, port))
		return sock

	except (OSError, ssl.SSLError) as exc:
		print(exc)
		return None


def upstream_close(sock):
	"""
	Teardown a secure SSL/TLS connection to a upstream server.

	Params:
		sock - secure socket object to close
	"""

	# Close underlying socket connection
	sock.shutdown(socket.SHUT_RDWR)
	sock.close()


def upstream_forward(sock, data):
	"""
	Forward a DNS request to a upstream server using TLS.

	Params:
		sock - socket object connected to upstream server
		data - wireformat DNS request packet to forward

	Returns:
		A wireformat DNS response packet

	Notes:
		Using DNS over TLS format as described here:
		https://tools.ietf.org/html/rfc7858
	"""

	sock.send(struct.pack('!H', len(data)) + data)
	return sock.recv(4096)[2:]


if __name__ == '__main__':
	main()

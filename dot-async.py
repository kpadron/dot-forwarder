#!/usr/bin/env python3
import asyncio, struct
import random, datetime


listen_host = '127.0.0.1'
listen_port = 5053
upstreams = [
	['1.1.1.1', 853, 'cloudflare-dns.com', 0.0],
	['8.8.8.8', 853, 'dns.google', 0.0],
	['9.9.9.9', 853, 'dns.quad9.net', 0.0],
	]


def main():
	loop = asyncio.get_event_loop()
	transports = []

	# Setup listening servers
	print('Starting UDP server listening on %s#%d' % (listen_host, listen_port))
	udp_listen = loop.create_datagram_endpoint(UdpDotProtocol, (listen_host, listen_port), reuse_address=True)
	transport, _ = loop.run_until_complete(udp_listen)
	transports.append(transport)
	print('Starting TCP server listening on %s#%d' % (listen_host, listen_port))
	tcp_listen = loop.create_server(TcpDotProtocol, listen_host, listen_port, reuse_address=True)
	transport = loop.run_until_complete(tcp_listen)
	transports.append(transport)

	# Serve forever
	try:
		loop.run_forever()
	except (KeyboardInterrupt, SystemExit):
		pass

	# Close listening servers
	for transport in transports:
		transport.close()

	loop.run_until_complete(asyncio.sleep(0.3))
	loop.close()


class UdpDotProtocol(asyncio.DatagramProtocol):
	"""
	Protocol for serving UDP DNS requests via DNS over TLS.
	"""

	def connection_made(self, transport):
		self.transport = transport

	def connection_lost(self, exc):
		pass

	def datagram_received(self, data, addr):
		# Schedule packet forwarding coroutine
		asyncio.ensure_future(self.process_packet(addr, data))

	def error_received(self, exc):
		print(exc)

	async def process_packet(self, addr, query):
		# Select upstream server to forward to
		upstream = upstream_select(upstreams)

		# Forward DNS query to upstream server
		answer = await upstream_forward(upstream, struct.pack('!H', len(query)) + query)

		# Forward DNS answer to client
		self.transport.sendto(answer[2:], addr)


class TcpDotProtocol(asyncio.Protocol):
	"""
	Protocol for serving TCP DNS requests via DNS over TLS.
	"""

	def connection_made(self, transport):
		self.transport = transport

	def connection_lost(self, exc):
		if not self.transport.is_closing():
			self.transport.close()

	def data_received(self, data):
		asyncio.ensure_future(self.process_packet(data))

	def eof_received(self):
		return None

	async def process_packet(self, query):
		# Select upstream server to forward to
		upstream = upstream_select(upstreams)

		# Forward DNS query to upstream server
		answer = await upstream_forward(upstream, query)

		# Forward DNS answer to client
		self.transport.write(answer)


async def upstream_forward(upstream, query):
	"""
	Forward a DNS request to a upstream server using TLS.

	Params:
		upstream - upstream server to forward requests to
		query    - wireformat DNS request packet to forward (length prefixed)

	Returns:
		A wireformat DNS response packet (length prefixed)

	Notes:
		Using DNS over TLS format as described here:
		https://tools.ietf.org/html/rfc7858
	"""

	try:
		# Establish upstream connection
		reader, writer = None, None
		reader, writer = await asyncio.open_connection(upstream[0], upstream[1], ssl=True, server_hostname=upstream[2])

		# Forward request upstream
		writer.write(query)
		await writer.drain()
		rtt = get_epoch_ms()

		# Wait for response
		answer = await reader.read(65537)
		rtt = get_epoch_ms() - rtt

		# Update estimated RTT for this upstream connection
		upstream[3] = 0.875 * upstream[3] + 0.125 * rtt

		# Return response
		return answer

	except Exception as exc:
		print('Encountered exception while attempting to forward query to upstream ' + str(exc))
		upstream[3] = upstream[3] + 1
		return b'\x00\x00'

	finally:
		# Teardown upstream connection
		if writer is not None:
			writer.close()


def upstream_select(upstreams):
	"""
	Select a upstream server to connect to (biases towards upstreams with lower rtt).

	Params:
		upstreams - list of upstream servers

	Returns:
		The selected upstream server.
	"""

	max_rtt = max([upstream[3] for upstream in upstreams])
	return random.choices(upstreams, [max_rtt - upstream[3] + 1 for upstream in upstreams])[0]


def get_epoch_ms():
	"""
	Returns the current number of milliseconds since the Epoch.
	"""

	return (datetime.datetime.utcnow() - datetime.datetime.utcfromtimestamp(0)).total_seconds() * 1000.0


if __name__ == '__main__':
	main()

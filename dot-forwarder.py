#!/usr/bin/env python3
import socket, ssl
import struct, random
import time, asyncio


def main():
	listen_host = '127.0.0.1'
	listen_port = 5053

	upstreams = \
	[
		UpstreamContext('1.1.1.1', 853, 'cloudflare-dns.com'),
		UpstreamContext('8.8.8.8', 853, 'dns.google'),
		UpstreamContext('9.9.9.9', 853, 'dns.quad9.net'),
	]

	resolver = DotResolver(upstreams)
	loop = asyncio.get_event_loop()
	transports = []

	# Setup listening servers
	print('Starting UDP server listening on %s#%d' % (listen_host, listen_port))
	udp_listen = loop.create_datagram_endpoint(lambda: UdpDotProtocol(resolver), (listen_host, listen_port), reuse_address=True)
	transport, _ = loop.run_until_complete(udp_listen)
	transports.append(transport)
	print('Starting TCP server listening on %s#%d' % (listen_host, listen_port))
	tcp_listen = loop.create_server(lambda: TcpDotProtocol(resolver), listen_host, listen_port, reuse_address=True)
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


class TransportStream:
	"""
	An object used to manage a generic stream over a transport protocol.
	"""

	def __init__(self, handle, reader=None, writer=None):
		self.handle = handle
		self.reader = reader
		self.writer = writer

	def is_active(self):
		"""
		Returns a boolean indicating if the stream is still active (and useable).
		"""

		if self.writer is None or self.writer.transport.is_closing():
			return False

		return True

	def close(self):
		"""
		Close the underlying transport connection for this stream.
		"""

		if self.is_active():
			self.writer.close()


class UpstreamContext:
	"""
	An object used to manage upstream server connections and metadata.
	"""

	def __init__(self, host=None, port=None, auth_name=None):
		self.host = host
		self.port = port
		self.auth_name = auth_name
		self.rtt = 0.0
		self.queries = 0
		self.answers = 0
		self._streams = {}
		self._stream_handle = 0

	def get_stats(self):
		"""
		Returns a formatted string of statistics for this upstream server.
		"""

		return '%s#%u [%s] (rtt: %.2f ms, queries: %u, answers: %u)' % (self.host, self.port, self.auth_name, self.rtt, self.queries, self.answers)

	async def _open_stream(self, handle):
		"""
		Returns a transport stream connected to the upstream.
		"""

		reader, writer = await asyncio.open_connection(self.host, self.port, ssl=True, server_hostname=self.auth_name)
		return TransportStream(handle, reader, writer)

	async def get_stream(self):
		"""
		Returns a transport stream to be used for forwarding queries upstream.
		"""
		self.queries += 1

		handle = self._stream_handle
		self._stream_handle += 1
		return await self._open_stream(handle)

	def release_stream(self, stream_handle):
		"""
		Releases a previously requested transport stream.
		"""

		self._streams[stream_handle].close()
		del self._streams[stream_handle]
		self.answers += 1


class DotResolver:
	"""
	An object used to manager upstream server contexts and resolve DNS over TLS queries.
	"""

	def __init__(self, upstreams=[UpstreamContext('1.1.1.1', 853, 'cloudflare-dns.com')]):
		self._upstreams = upstreams
		self._queries = 0
		self._answers = 0

	def _select_upstream_rtt(self):
		"""
		Select a upstream server to forward to (biases towards upstreams with lower rtt).

		Returns:
			The selected upstream server.
		"""

		max_rtt = max([upstream.rtt for upstream in self._upstreams])
		return random.choices(self._upstreams, [max_rtt - upstream.rtt + 1 for upstream in self._upstreams])[0]

	def _select_upstream_random(self):
		"""
		Select a upstream server to forward to (random even distribution).

		Returns:
			The selected upstream server.
		"""

		return self._upstreams[random.randint(0, len(self._upstreams) - 1)]

	async def resolve(self, query):
		"""
		Resolve DNS query via forwarding to upstream DoT server.

		Params:
			query - wireformat DNS request packet to forward (length prefixed)

		Returns:
			A wireformat DNS response packet (length prefixed)

		Notes:
			Using DNS over TLS format as described here:
			https://tools.ietf.org/html/rfc7858
		"""

		stream = None

		try:
			# Select upstream to connect to
			upstream = self._select_upstream_rtt()

			# Establish upstream connection
			stream = await upstream.get_stream()

			# Forward request upstream
			stream.writer.write(query)
			await stream.writer.drain()
			rtt = time.monotonic()
			self._queries += 1

			# Wait for response
			answer = await stream.reader.read(65537)
			rtt = time.monotonic() - rtt
			self._answers += 1

			# Update estimated RTT for this upstream connection
			upstream.rtt = 0.875 * upstream.rtt + 0.125 * rtt

			# Reset RTT every 1000 processed requests to prevent drift
			if self._answers % 1000 == 0:
				for u in self._upstreams:
					print(u.get_stats())
					u.rtt = 0.0

			# Return response
			return answer

		except Exception as exc:
			print(exc)
			upstream.rtt += 1000.0
			return b'\x00\x00'

		finally:
			# Teardown upstream connection
			if stream is not None:
				upstream.release_stream(stream.handle)


class UdpDotProtocol(asyncio.DatagramProtocol):
	"""
	Protocol for serving UDP DNS requests via DNS over TLS.
	"""

	def __init__(self, resolver=DotResolver()):
		self.resolver = resolver

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
		# Resolve DNS query
		answer = await self.resolver.resolve(struct.pack('!H', len(query)) + query)

		# Send DNS answer to client
		self.transport.sendto(answer[2:], addr)


class TcpDotProtocol(asyncio.Protocol):
	"""
	Protocol for serving TCP DNS requests via DNS over TLS.
	"""

	def __init__(self, resolver=DotResolver()):
		self.resolver = resolver

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
		# Resolve DNS query
		answer = await self.resolver.resolve(query)

		# Forward DNS answer to client
		self.transport.write(answer)


if __name__ == '__main__':
	main()

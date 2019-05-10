#!/usr/bin/env python3
import struct, random
import socket, ssl
import argparse, logging
import asyncio as aio
import dnslib as dns
from typing import Sequence, Tuple

def main():
	# Handle command line arguments
	parser = argparse.ArgumentParser()
	parser.add_argument('-l', '--listen-address', nargs='+', default=['127.0.0.1', '::1'],
						help='addresses to listen on for DNS over TLS requests (default: %(default)s)')
	parser.add_argument('-p', '--listen-port', nargs='+', type=int, default=[53],
						help='ports to listen on for DNS over TLS requests (default: %(default)s)')
	parser.add_argument('-u', '--upstreams', nargs='+', default=['1.1.1.1', '1.0.0.1'],
						help='upstream servers to forward DNS queries and requests to (default: %(default)s)')
	parser.add_argument('-a', '--authnames', nargs='+', default=['cloudflare-dns.com', 'cloudflare-dns.com'],
						help='hostname of upstream servers used for verification (default: %(default)s)')
	parser.add_argument('-t', '--tcp', action='store_true', default=False,
						help='serve TCP based queries and requests along with UDP (default: %(default)s)')
	args = parser.parse_args()

	# Setup logging
	logging.basicConfig(level='INFO', format='[%(levelname)s] %(message)s')
	logging.info('Starting DNS over TLS proxy server')
	logging.info('Args: %r' % (vars(args)))
	loop = aio.get_event_loop()

	# Configure upstream servers
	upstreams = []
	for upstream, authname in zip(args.upstreams, args.authnames):
		upstreams.append(DotStream((upstream, 853), authname))

	# Initialize DNS over TLS resolver
	resolver = DotResolver(tuple(upstreams))

	# Setup listening transports
	transports = []
	for address in args.listen_address:
		for port in args.listen_port:
			# Setup UDP server
			logging.info('Starting UDP server listening on [%s#%d]' % (address, port))
			udp = loop.create_datagram_endpoint(lambda: DotUdpServer(resolver), (address, port), reuse_address=True)
			udp, _ = loop.run_until_complete(udp)
			transports.append(udp)

			# Setup TCP server
			if args.tcp:
				logging.info('Starting TCP server listening on [%s#%d]' % (address, port))
				tcp = aio.start_server(DotTcpServer(resolver).service_client, address, port, reuse_address=True)
				tcp = loop.run_until_complete(tcp)
				transports.append(tcp)

	# Serve forever
	try:
		loop.run_forever()
	except (KeyboardInterrupt, SystemExit):
		logging.info('Stopping DNS over TLS proxy server')

	# Close listening servers
	logging.info('Closing listening servers')
	for transport in transports:
		transport.close()

	# Disconnect from all upstream servers
	logging.info('Closing upstream connections')
	loop.run_until_complete(resolver.close())

	# Cleanup event loop
	loop.run_until_complete(loop.shutdown_asyncgens())
	loop.run_until_complete(aio.sleep(0.3))
	loop.close()


class DotStream:
	"""
	A DNS over TLS stream connection to a upstream server.

	Attributes:
		max_retries: The maximum number of retry attempts per send_query.
	"""
	max_retries: int = 1

	def __init__(self, address: Tuple[str, int], authname: str, loop: aio.AbstractEventLoop = None) -> None:
		"""
		Initialize a DotStream instance.

		Args:
			address: The (host, port) tuple of the upstream server.
			authname: The hostname to use for verifying the upstream server.
			loop: The async event loop to run on (defaults to current running loop).

		Attributes:
			address: The (host, port) tuple of the upstream server.
			authname: The hostname to use for verifying the upstream server.
			rtt: The estimated RTT to the upstream server.
		"""
		self.address = address
		self.authname = authname
		self.rtt = 0.0
		self._stream = None
		self._context = ssl.create_default_context()
		self._loop = loop or aio.get_event_loop()
		self._clock = aio.Lock(loop=self._loop)
		self._rlock = aio.Lock(loop=self._loop)
		self._wlock = aio.Lock(loop=self._loop)

	def is_closed(self) -> bool:
		"""Returns a boolean indicating if the transport stream is closed."""
		return self._stream is None or self._stream[1].is_closing()

	async def connect(self) -> None:
		"""Asynchronously connect to the upstream server if not yet connected."""
		async with self._clock:
			if self.is_closed():
				# Create non-blocking TCP socket with keep-alive and disable nagle's algorithm
				sock = socket.socket()
				sock.setblocking(False)
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
				sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1)
				sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 3)
				sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
				sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

				# Connect to upstream server over TCP transport
				await self._loop.sock_connect(sock, self.address)

				# Connect to upstream server over encrypted TLS session
				self._stream = await aio.open_connection(
					loop=self._loop, ssl=self._context,
					sock=sock, server_hostname=self.authname,
					ssl_handshake_timeout=2.5)

	async def disconnect(self) -> None:
		"""Asynchronously disconnect from the upstream server if currently connected."""
		async with self._clock:
			if self._stream is not None:
				writer = self._stream[1]
				self._stream = None
				if not writer.is_closing():
					writer.close()
					await writer.wait_closed()

	async def send_query(self, query: bytes) -> bool:
		"""
		Asynchronously send a DNS query to the upstream server.

		Args:
			query: The UDP wireformat DNS query packet to forward.

		Returns:
			True if query is successfully sent, False otherwise.

		Note:
			DNS query is formatted before being sent per RFC7858 including two-octet length prefix
			https://tools.ietf.org/html/rfc7858
		"""
		prefix = struct.pack('!H', len(query))

		for _ in range(DotStream.max_retries + 1):
			try:
				await self.connect()

				async with self._wlock:
					writer = self._stream[1]
					writer.write(prefix + query)
					await writer.drain()

				return True

			except ConnectionError as exc:
				logging.error('DotStream::send_query %r: %r' % (self.address, exc))
				await self.disconnect()

		return False

	async def recv_answer(self) -> bytes:
		"""
		Asynchronously receive a DNS answer from the upstream server.

		Returns:
			The UDP wireformat DNS answer packet.
		"""
		try:
			async with self._rlock:
				reader = self._stream[0]
				prefix = await reader.readexactly(2)
				return await reader.readexactly(struct.unpack('!H', prefix)[0])

		except Exception:
			return b''


class DotResolver:
	"""
	A DNS over TLS resolver that forwards requests to configured upstream servers.

	Attributes:
		max_retries: The maximum number of retry attempts per resolution.
		request_timeout: The maximum wait time per resolution (in seconds).
	"""
	max_retries: int = 2
	request_timeout: float = 3.5

	def __init__(self, upstreams: Sequence[DotStream], loop: aio.AbstractEventLoop = None):
		"""
		Initialize a DotResolver instance.

		Args:
			upstreams: A sequence of DotStream instances to use for forwarding queries.
			loop: The async event loop to run on (defaults to current running loop).
		"""
		self._upstreams = upstreams
		self._loop = loop or aio.get_event_loop()
		self._queries = 0
		self._responses = {}
		self._events = {}

	async def close(self) -> None:
		"""Asynchronously closes all connections to upstream servers."""
		for upstream in self._upstreams:
			await upstream.disconnect()

	async def resolve(self, request: dns.DNSRecord) -> dns.DNSRecord:
		"""
		Resolves a DNS request asynchronously via forwarding to a DNS over TLS upstream server.

		Args:
			request: The DNS request to resolve (modified by this method).

		Returns:
			The corresponding DNS response.
		"""
		try:
			# Create skeleton DNS response
			response = request.reply()

			# Assign a query id to this request (used for tracking)
			query_id = self._queries % 65536
			self._queries += 1

			# Reset upstream RTTs to prevent drift
			if self._queries % 10000 == 0:
				logging.info('DotResolver::resolve: total_queries = %d' % (self._queries))
				for upstream in self._upstreams:
					logging.info('DotResolver::resolve %r: avg_rtt = %f' % (upstream.address, upstream.rtt))
					upstream.rtt = 0.0

			# Add request to active tracking
			self._events[query_id] = aio.Event(loop=self._loop)
			request.header.id = query_id

			for _ in range(DotResolver.max_retries + 1):
				# Select a upstream server to forward to
				upstream = self._select_upstream_rtt()

				# Forward a query packet to the upstream server
				rtt = self._loop.time()
				if await upstream.send_query(request.pack()):
					break
			else:
				raise Exception('max retries reached')

			# Schedule the response to be processed
			self._loop.create_task(self._process_response(upstream))

			# Wait for request to be serviced
			await aio.wait_for(self._events[query_id].wait(), DotResolver.request_timeout, loop=self._loop)

			# Fill out response
			reply = self._responses[query_id]
			response.add_answer(*reply.rr)
			response.add_auth(*reply.auth)
			response.add_ar(*reply.ar)

		except Exception as exc:
			logging.error('DotResolver::resolve %r %d: %r' % (upstream.address, query_id, exc))
			response.header.rcode = getattr(dns.RCODE, 'SERVFAIL')

		finally:
			# Update RTT estimation for selected upstream server
			rtt = self._loop.time() - rtt
			upstream.rtt = 0.875 * upstream.rtt + 0.125 * rtt

			# Remove this request from tracking
			self._responses.pop(query_id, None)
			self._events.pop(query_id, None)

			return response

	async def _process_response(self, upstream: DotStream) -> None:
		try:
			# Receive an answer packet from the upstream server
			answer = await upstream.recv_answer()

			# An error occurred with the upstream connection
			if not answer:
				raise Exception('failed to receive DNS answer from upstream server')

			# Parse DNS answer packet into a response
			response = dns.DNSRecord.parse(answer)

			# Add response and signal response complete
			if response.header.id in self._events:
				self._responses[response.header.id] = response
				self._events[response.header.id].set()

		except Exception as exc:
			logging.error('DotResolver::_process_response %r: %r' % (upstream.address, exc))

	def _select_upstream_random(self) -> DotStream:
		return random.choice(self._upstreams)

	def _select_upstream_rtt(self) -> DotStream:
		max_rtt:float = max(upstream.rtt for upstream in self._upstreams)
		return random.choices(self._upstreams, tuple(max_rtt - upstream.rtt + 1.0 for upstream in self._upstreams))[0]


class DotUdpServer(aio.DatagramProtocol):
	max_udp_size: int = 512

	def __init__(self, resolver: DotResolver, loop: aio.AbstractEventLoop = None) -> None:
		self._resolver = resolver
		self._loop = loop or aio.get_event_loop()
		self._transport = None

	def connection_made(self, transport: aio.DatagramTransport) -> None:
		self._transport = transport

	def datagram_received(self, data: bytes, addr: tuple) -> None:
		self._loop.create_task(self._process_query(addr, data))

	async def _process_query(self, client: tuple, query: bytes) -> None:
		try:
			# Parse DNS query packet into a request
			request = dns.DNSRecord.parse(query)
			response = await self._resolver.resolve(request)

			# Pack DNS response into answer packet and truncate if necessary
			answer = response.pack()
			if len(answer) > DotUdpServer.max_udp_size:
				answer = response.truncate().pack()

		# Failed to parse DNS query
		except dns.DNSError:
			answer = dns.DNSRecord(dns.DNSHeader(rcode=getattr(dns.RCODE, 'FORMERR'))).pack()

		# Reply to client with DNS answer
		finally:
			self._transport.sendto(answer, client)


class DotTcpServer:
	def __init__(self, resolver: DotResolver) -> None:
		self._resolver = resolver

	async def service_client(self, reader: aio.StreamReader, writer: aio.StreamWriter) -> None:
		try:
			while True:
				# Parse DNS query packet into a request
				prefix = await reader.readexactly(2)
				query = await reader.readexactly(struct.unpack('!H', prefix)[0])
				request = dns.DNSRecord.parse(query)

				response = await self._resolver.resolve(request)

				# Pack DNS response into answer
				answer = response.pack()
				writer.write(struct.pack('!H', len(answer)) + answer)
				await writer.drain()

		# Connection likely closed or reset by client
		except aio.IncompleteReadError:
			pass

		# Failed to parse DNS query
		except dns.DNSError:
			writer.write(dns.DNSRecord(dns.DNSHeader(rcode=getattr(dns.RCODE, 'FORMERR'))).pack())
			await writer.drain()

		# Cleanly close client connection
		finally:
			if not writer.is_closing():
				writer.close()
				await writer.wait_closed()


if __name__ == '__main__':
	main()

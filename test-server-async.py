#!/usr/bin/env python3
from typing import Sequence
import struct, random, time
import argparse, logging, copy
import asyncio as aio
import dnslib as dns
# import dnslib.server as dns_server

def main():
	loop = aio.get_event_loop()

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

	# Setup upstream configuration
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
	max_retries: int = 1

	def __init__(self, address: tuple, authname: str) -> None:
		self.address = address
		self.authname = authname
		self._stream = None
		self._clock = aio.Lock()
		self._rlock = aio.Lock()
		self._wlock = aio.Lock()

	def is_closed(self) -> bool:
		return self._stream is None or self._stream[1].is_closing()

	async def connect(self) -> None:
		async with self._clock:
			if self.is_closed():
				self._stream = await aio.open_connection(*self.address, ssl=True, server_hostname=self.authname)

	async def disconnect(self) -> None:
		async with self._clock:
			if self._stream is not None:
				writer = self._stream[1]
				self._stream = None
				if not writer.is_closing():
					writer.close()
					await writer.wait_closed()

	async def send_query(self, query: bytes) -> None:
		for _ in range(DotStream.max_retries + 1):
			try:
				await self.connect()

				async with self._wlock:
					writer = self._stream[1]
					writer.write(struct.pack('!H', len(query)) + query)
					await writer.drain()

				return True

			except Exception as exc:
				logging.error('DotStream::send_query: ' + repr(exc))
				await self.disconnect()

		return False

	async def recv_answer(self) -> bytes:
		try:
			async with self._rlock:
				reader = self._stream[0]
				prefix = await reader.readexactly(2)
				return await reader.readexactly(struct.unpack('!H', prefix)[0])

		except Exception:
			return b''


class DotResolver:
	max_retries: int = 2
	request_timeout: float = 3.5

	def __init__(self, upstreams: Sequence[DotStream]):
		self._upstreams = upstreams
		self._queries = 0
		self._responses = {}
		self._events = {}

	async def close(self) -> None:
		for upstream in self._upstreams:
			await upstream.disconnect()

	async def resolve(self, request: dns.DNSRecord) -> dns.DNSRecord:
		try:
			# Create skeleton DNS response
			response = request.reply()

			# Assign a query id to this request (used for tracking)
			query_id = self._queries % 65536
			self._queries += 1

			# Add request to active tracking
			self._events[query_id] = aio.Event()
			request.header.id = query_id

			for _ in range(DotResolver.max_retries + 1):
				# Select upstream server to forward to
				upstream = self._select_upstream_random()

				# Forward a query packet to the upstream server
				if await upstream.send_query(request.pack()):
					break
			else:
				raise Exception('max retries reached')

			# Schedule the response to be processed
			aio.create_task(self._process_response(upstream))

			# Wait for request to be serviced
			await aio.wait_for(self._events[query_id].wait(), DotResolver.request_timeout)

			# Fill out response
			reply = self._responses[query_id]
			response.add_answer(*reply.rr)
			response.add_auth(*reply.auth)
			# response.add_ar(*reply.ar)

		except Exception as exc:
			logging.error('DotResolver::resolve: %r %d ' % (upstream.address, query_id) + repr(exc))
			response.header.rcode = getattr(dns.RCODE, 'SERVFAIL')

		finally:
			# Remove this request from tracking
			self._responses.pop(query_id, None)
			self._events.pop(query_id, None)

			return response

	async def _process_response(self, upstream: DotStream) -> None:
		try:
			# Receive an answer packet from the upstream server
			answer = await upstream.recv_answer()

			# An error occurred with the upstream connection
			if answer == b'':
				raise Exception('failed to receive DNS answer from upstream')

			# Parse DNS answer packet into a response
			response = dns.DNSRecord.parse(answer)

			# Add response and signal response complete
			if response.header.id in self._events:
				self._responses[response.header.id] = response
				self._events[response.header.id].set()

		except Exception as exc:
			logging.error('DotResolver::_process_response: ' + repr(exc))

	def _select_upstream_random(self) -> DotStream:
		return random.choice(self._upstreams)

	def _select_upstream_rtt(self) -> DotStream:
		max_rtt: float = max(upstream.rtt for upstream in self._upstreams)
		return random.choices(self._upstreams, tuple(max_rtt - upstream.rtt + 1.0 for upstream in self._upstreams))[0]


class DotUdpServer(aio.DatagramProtocol):
	max_udp_size: int = 512

	def __init__(self, resolver: DotResolver) -> None:
		self._resolver = resolver
		self._transport = None

	def connection_made(self, transport):
		self._transport = transport

	def connection_lost(self, exc):
		logging.error(repr(exc))

	def datagram_received(self, data, addr):
		aio.create_task(self.process_query(addr, data))

	def error_received(self, exc):
		logging.error('DotUdpServer::error_received: ' + repr(exc))

	async def process_query(self, client: tuple, query: bytes) -> None:
		try:
			# Parse DNS query packet into a request
			request = dns.DNSRecord.parse(query)
			response = await self._resolver.resolve(request)

			# Pack DNS response into answer packet and truncate if necessary
			answer = response.pack()
			if len(answer) > DotUdpServer.max_udp_size:
				answer = response.truncate().pack()

		except dns.DNSError as exc:
			answer = dns.DNSRecord(dns.DNSHeader(rcode=getattr(dns.RCODE, 'FORMERR'))).pack()

		except Exception as exc:
			logging.error('DotUdpServer::process_query: ' + repr(exc))
			response = request.reply()
			response.header.rcode = getattr(dns.RCODE, 'SERVFAIL')
			answer = response.pack()

		finally:
			self._transport.sendto(answer, client)


class DotTcpServer:
	def __init__(self, resolver: DotResolver) -> None:
		self._resolver = resolver

	async def service_client(self, reader, writer):
		try:
			while True:
				prefix = await reader.readexactly(2)
				query = await reader.readexactly(struct.unpack('!H', prefix)[0])

				request = dns.DNSRecord.parse(query)
				response = await self._resolver.resolve(request)

				answer = response.pack()
				writer.write(struct.pack('!H', len(answer)) + answer)
				await writer.drain()

				if reader.at_eof():
					break

		except aio.IncompleteReadError:
			pass

		except dns.DNSError as exc:
			writer.write(dns.DNSRecord(dns.DNSHeader(rcode=getattr(dns.RCODE, 'FORMERR'))).pack())
			await writer.drain()

		except Exception as exc:
			logging.error('DotTcpServer::service_client: ' + repr(exc))

		finally:
			if not writer.is_closing():
				writer.close()
				await writer.wait_closed()


if __name__ == '__main__':
	main()

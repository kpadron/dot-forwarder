#!/usr/bin/env python3
import struct, random, time
import argparse, logging
import asyncio as aio
import dnslib as dns
import dnslib.server as dns_server
from typing import Sequence

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
		upstreams.append(DotUpstream((upstream, 853), authname))

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
	def __init__(self, address: tuple, authname: str) -> None:
		self._address = address
		self._authname = authname
		self._clock = aio.Lock()
		self._rlock = aio.Lock()
		self._wlock = aio.Lock()
		self._stream = None
		self._tasks = 0

	def in_use(self) -> bool:
		return bool(self._tasks)

	def is_closed(self) -> bool:
		return self._stream is None or self._stream[1].is_closing()

	async def connect(self) -> None:
		async with self._clock:
			if self._stream is None:
				self._stream = await aio.open_connection(*self._address, ssl=True, server_hostname=self._authname)

	async def disconnect(self) -> None:
		async with self._clock:
			if self._stream is not None:
				writer = self._stream[1]
				self._stream = None
				if not writer.is_closing():
					writer.close()
					await writer.wait_closed()

	async def send_query(self, query: bytes) -> None:
		async with self._wlock:
			if self._stream is None:
				return

			writer = self._stream[1]
			writer.write(struct.pack('!H', len(query)) + query)
			await writer.drain()

	async def recv_answer(self) -> bytes:
		async with self._rlock:
			if self._stream is None:
				return b''

			reader = self._stream[0]
			prefix = await reader.readexactly(2)
			return await reader.readexactly(struct.unpack('!H', prefix)[0])

	async def forward_query(self, query: bytes) -> bytes:
		self._tasks += 1
		answer = b''

		try:
			await self.connect()
			await self.send_query(query)
			answer = await self.recv_answer()

		except Exception as exc:
			logging.error('DotStream::forward_query ' + repr(exc))
			await self.disconnect()

		finally:
			self._tasks -= 1
			return answer


class DotUpstream:
	max_streams: int = 3
	max_retries: int = 2

	def __init__(self, address: tuple, authname: str) -> None:
		self._streams = tuple(DotStream(address, authname) for _ in range(DotUpstream.max_streams))
		self._rtt = 0.0

	@property
	def rtt(self) -> float:
		return self._rtt

	@rtt.setter
	def rtt(self, rtt: float) -> None:
		self._rtt = rtt

	async def close(self) -> None:
		for stream in self._streams:
			await stream.disconnect()

	async def forward_query(self, query: bytes) -> bytes:
		answer: bytes = b''
		rtt: float = time.monotonic()

		for _ in range(DotUpstream.max_retries + 1):
			stream = self._select_stream()
			answer = await stream.forward_query(query)

			if answer != b'':
				break

		rtt = time.monotonic() - rtt
		self._rtt = 0.875 * self._rtt + 0.125 * rtt
		return answer

	def _select_stream(self) -> DotStream:
		for stream in self._streams:
			if not stream.in_use() and not stream.is_closed():
				break
		else:
			stream = None

		if stream is not None:
			return stream

		return random.choice(self._streams)


class DotResolver:
	max_retries: int = 2

	def __init__(self, upstreams: Sequence[DotUpstream]):
		assert len(upstreams), 'A non-empty sequence of DotUpstream is required'
		self._upstreams = upstreams
		self._queries = 0

	async def close(self) -> None:
		for upstream in self._upstreams:
			await upstream.close()

	async def resolve(self, request: dns.DNSRecord) -> dns.DNSRecord:
		try:
			response = request.reply()

			self._queries += 1
			if self._queries % 10000 == 0:
				for upstream in self._upstreams:
					upstream.rtt = 0.0

			for _ in range(DotResolver.max_retries + 1):
				upstream = self._select_upstream_rtt()
				answer = await upstream.forward_query(request.pack())

				if answer != b'':
					reply = dns.DNSRecord.parse(answer)
					response.add_answer(*reply.rr)
					response.add_auth(*reply.auth)
					# response.add_ar(*reply.ar)
					break
			else:
				raise Exception('max retries exceeded')

		except Exception as exc:
			logging.error('DotResolver::resolve ' + repr(exc))
			response.header.rcode = getattr(dns.RCODE, 'SERVFAIL')

		finally:
			return response

	def _select_upstream_random(self) -> DotUpstream:
		return random.choice(self._upstreams)

	def _select_upstream_rtt(self) -> DotUpstream:
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
		logging.error(repr(exc))

	async def process_query(self, client: tuple, query: bytes) -> None:
		try:
			request = dns.DNSRecord.parse(query)
			response = await self._resolver.resolve(request)
			answer = response.pack()

			if len(answer) > DotUdpServer.max_udp_size:
				answer = response.truncate().pack()

		except dns.DNSError as exc:
			logging.error('DotUdpServer::process_query' + repr(exc))
			answer = dns.DNSRecord(dns.DNSHeader(rcode=getattr(dns.RCODE, 'FORMERR'))).pack()

		except Exception as exc:
			logging.error('DotUdpServer::process_query' + repr(exc))
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
			logging.error('DotTcpServer::service_client' + repr(exc))
			writer.write(dns.DNSRecord(dns.DNSHeader(rcode=getattr(dns.RCODE, 'FORMERR'))).pack())
			await writer.drain()

		except Exception as exc:
			logging.error('DotTcpServer::service_client' + repr(exc))

		finally:
			if not writer.is_closing():
				writer.close()
				await writer.wait_closed()


if __name__ == '__main__':
	main()

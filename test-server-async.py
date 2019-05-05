#!/usr/bin/env python3
import struct, random, logging, time
import asyncio as aio
import dnslib as dns
import dnslib.server as dns_server
from typing import Sequence


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

	def _select_stream(self) -> DotStream:
		for stream in self._streams:
			if not stream.in_use() and not stream.is_closed():
				break
		else:
			stream = None

		if stream is not None:
			return stream

		return random.choice(self._streams)

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


class DotResolver:
	max_retries: int = 2

	def __init__(self, upstreams: Sequence[DotUpstream]) -> None:
		assert len(upstreams), 'A non-empty sequence of DotUpstream is required'
		self._upstreams = upstreams

	def _select_upstream_random(self) -> DotUpstream:
		return random.choice(self._upstreams)

	def _select_upstream_rtt(self) -> DotUpstream:
		max_rtt: float = max(upstream.rtt for upstream in self._upstreams)
		return random.choices(self._upstreams, tuple(max_rtt - upstream.rtt + 1.0 for upstream in self._upstreams))[0]

	async def close(self) -> None:
		for upstream in self._upstreams:
			await upstream.close()

	async def resolve(self, request: dns.DNSRecord) -> dns.DNSRecord:
		response = request.reply()

		try:
			for _ in range(self.max_retries + 1):
				upstream = self._select_upstream_rtt()
				answer = await upstream.forward_query(request.pack())

				if answer != b'':
					reply = dns.DNSRecord.parse(answer)
					response.add_answer(*reply.rr)
					response.add_auth(*reply.auth)
					# response.add_ar(*reply.ar)
					break
			else:
				raise Exception('DotResolver::resolve max retries exceeded')

		except Exception as exc:
			logging.error('DotResolver::resolve ' + repr(exc))
			response.header.rcode = getattr(dns.RCODE, 'SERVFAIL')

		finally:
			return response


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
		except dns.DNSError as exc:
			logging.error(repr(exc))
			self._transport.sendto(dns.DNSRecord(dns.DNSHeader(rcode=getattr(dns.RCODE, 'FORMERR'))).pack(), client)
			return

		logging.info('DotUdpServer::process_query [%s#%d<%d>] %s %r' % (client[0], client[1], request.header.id, dns.OPCODE.get(request.header.opcode), request.q))
		rtt = time.monotonic()
		response = await self._resolver.resolve(request)
		rtt = time.monotonic() - rtt
		logging.info('DotUdpServer::process_query [%s#%d<%d>] %s(%.0fms) %r' % (client[0], client[1], response.header.id, dns.RCODE.get(response.header.rcode), rtt * 1000.0, response.a))

		answer = response.pack()

		if len(answer) > self.max_udp_size:
			truncated_response = response.truncate()
			answer = truncated_response.pack()

		self._transport.sendto(answer, client)


def main():
	logging.basicConfig(level='INFO', format='[%(levelname)s] %(message)s')
	listen_address = ('127.0.0.1', 5001)

	upstreams = \
	(
		DotUpstream(('1.1.1.1', 853), 'cloudflare-dns.com'),
		DotUpstream(('1.0.0.1', 853), 'cloudflare-dns.com'),
		# DotUpstream(('8.8.8.8', 853), 'dns.google'),
		# DotUpstream(('9.9.9.9', 853), 'dns.quad9.net'),
	)

	resolver = DotResolver(upstreams)
	loop = aio.get_event_loop()
	transports = []

	# Setup listening servers
	logging.info('Starting UDP server listening on [%s#%d]' % (listen_address[0], listen_address[1]))
	udp_listen = loop.create_datagram_endpoint(lambda: DotUdpServer(resolver), listen_address, reuse_address=True)
	transport, _ = loop.run_until_complete(udp_listen)
	transports.append(transport)
	# print('Starting TCP server listening on %s#%d' % (listen_host, listen_port))
	# tcp_listen = loop.create_server(lambda: TcpDotProtocol(resolver), listen_host, listen_port, reuse_address=True)
	# transport = loop.run_until_complete(tcp_listen)
	# transports.append(transport)

	# Serve forever
	try:
		loop.run_forever()
	except (KeyboardInterrupt, SystemExit):
		pass

	# Close listening servers
	for transport in transports:
		if not transport.is_closing():
			transport.close()

	# Disconnect from all upstream servers
	loop.run_until_complete(resolver.close())

	loop.run_until_complete(loop.shutdown_asyncgens())
	loop.run_until_complete(aio.sleep(0.3))
	loop.close()


if __name__ == '__main__':
	main()

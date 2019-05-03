#!/usr/bin/env python3
import struct, random, logging
import asyncio as aio
import dnslib as dns
import dnslib.server as dns_server


class DotStream:
	def __init__(self, address, authname):
		self._address = address
		self._authname = authname
		self._socket = None
		self._session = None
		self._lock = aio.Lock()
		self._rlock = aio.Lock()
		self._wlock = aio.Lock()

	def in_use(self):
		return self._wlock.locked() or self._rlock.locked()

	async def connect(self):
		async with self._lock:
			if self._socket is None:
				self._socket = await aio.open_connection(*self._address, ssl=True, server_hostname=self._authname)

	async def disconnect(self):
		async with self._lock:
			if self._socket is not None:
				writer = self._socket[1]
				writer.close()

	async def send_query(self, query):
		async with self._wlock:
			if self._socket is None:
				return

			writer = self._socket[1]
			writer.write(struct.pack('!H', len(query)) + query)
			await writer.drain()

	async def recv_answer(self):
		async with self._rlock:
			if self._socket is None:
				return b''

			reader = self._socket[0]
			prefix = await reader.read(2)
			return await reader.read(struct.unpack('!H', prefix)[0])

	async def forward_query(self, query):
		try:
			await self.connect()
			await self.send_query(query)
			return await self.recv_answer()

		except Exception as exc:
			logging.error(exc)
			await self.disconnect()
			return b''


class DotUpstream:
	max_streams = 5

	def __init__(self, address, authname):
		self._streams = [DotStream(address, authname) for _ in range(self.max_streams)]

	def _select_stream(self):
		for stream in self._streams:
			if not stream.in_use():
				break
		else:
			stream = None

		if stream is not None:
			return stream

		return random.choice(self._streams)

	async def forward_query(self, query):
		stream = self._select_stream()
		return await stream.forward_query(query)


class DotResolver:
	def __init__(self, upstreams):
		self._upstreams = upstreams

	def _select_upstream_random(self):
		return random.choice(self._upstreams)

	async def resolve(self, request):
		response = request.reply()

		try:
			for _ in range(3):
				upstream = self._select_upstream_random()
				answer = await upstream.forward_query(request.pack())

				if answer != b'':
					reply = dns.DNSRecord.parse(answer)
					response.add_answer(*reply.rr)
					response.add_auth(*reply.auth)
					# response.add_ar(*reply.ar)
					break

		except Exception as exc:
			print(exc)
			response.header.rcode = getattr(dns.RCODE, 'SERVFAIL')

		return response


class DotUdpServer(aio.DatagramProtocol):
	max_udp_size = 512

	def __init__(self, resolver):
		super().__init__()
		self._resolver = resolver
		self._transport = None

	def connection_made(self, transport):
		self._transport = transport

	def connection_lost(self, exc):
		print(exc)

	def datagram_received(self, data, addr):
		aio.ensure_future(self.process_query(addr, data))

	def error_received(self, exc):
		print(exc)

	async def process_query(self, client, query):
		try:
			request = dns.DNSRecord.parse(query)
		except dns.DNSError as exc:
			print(exc)
			self._transport.sendto(dns.DNSRecord(dns.DNSHeader(rcode=getattr(dns.RCODE, 'FORMERR'))).pack(), client)
			return


		logging.info('Request: [%s#%d] %s (%s)' % (client[0], client[1], request.q.qname, dns.QTYPE[request.q.qtype]))
		response = await self._resolver.resolve(request)
		logging.info('Response: [%s#%d] %s (%s) / %s' % (client[0], client[1], response.q.qname, dns.QTYPE[response.q.qtype], ','.join([dns.QTYPE[a.rtype] for a in response.rr])))

		answer = response.pack()

		if len(answer) > self.max_udp_size:
			truncated_response = response.truncate()
			answer = truncated_response.pack()

		self._transport.sendto(answer, client)


def main():
	logging.basicConfig(level='INFO', format='[%(levelname)s] %(message)s')
	listen_address = ('127.0.0.1', 5001)

	upstreams = \
	[
		DotUpstream(('1.1.1.1', 853), 'cloudflare-dns.com'),
		DotUpstream(('1.0.0.1', 853), 'cloudflare-dns.com'),
		# DotUpstream(('8.8.8.8', 853), 'dns.google'),
		# DotUpstream(('9.9.9.9', 853), 'dns.quad9.net'),
	]

	resolver = DotResolver(upstreams)
	loop = aio.get_event_loop()
	transports = []

	# Setup listening servers
	print('Starting UDP server listening on %r' % (repr(listen_address)))
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
		transport.close()

	loop.run_until_complete(aio.sleep(0.3))
	loop.close()


if __name__ == '__main__':
	main()

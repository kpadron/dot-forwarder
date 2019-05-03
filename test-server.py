#!/usr/bin/env python3
import struct, random
import socket, ssl
import threading
import dnslib as dns
import dnslib.server as dns_server


class DotUpstream:
    def __init__(self, address, authname):
        self._address = address
        self._authname = authname
        self._socket = None
        self._lock = threading.RLock()
        self._rlock = threading.RLock()
        self._wlock = threading.RLock()

    def connect(self):
        with self._lock:
            if self._socket is None:
                self._socket = socket.create_connection(self._address)
                self._socket = ssl.create_default_context().wrap_socket(self._socket, suppress_ragged_eofs=False, server_hostname=self._authname)

    def disconnect(self):
        with self._lock:
            if self._socket is not None:
                self._socket.close()
                self._socket = None

    def send_query(self, query):
        with self._wlock:
            try:
                if self._socket is None:
                    return

                self._socket.send(struct.pack('!H', len(query)) + query)

            except Exception as exc:
                print(exc)
                self.disconnect()

    def recv_answer(self):
        with self._rlock:
            try:
                if self._socket is None:
                    return b''

                return self._socket.recv(struct.unpack('!H', self._socket.recv(2))[0])

            except Exception as exc:
                print(exc)
                self.disconnect()
                return b''

    def forward_query(self, query):
            try:
                self.connect()
                self.send_query(query)
                return self.recv_answer()

            except Exception as exc:
                print(exc)
                self.disconnect()
                return b''


class DotResolver(dns_server.BaseResolver):
    def __init__(self, upstreams):
        self._upstreams = upstreams

    def _select_upstream_random(self):
        return random.choice(self._upstreams)

    def resolve(self, request, handler):
        response = request.reply()

        try:
            for _ in range(3):
                upstream = self._select_upstream_random()
                answer = upstream.forward_query(request.pack())

                if answer == b'':
                    continue

                reply = dns.DNSRecord.parse(answer)
                response.add_answer(*reply.rr)
                response.add_auth(*reply.auth)
                # response.add_ar(*reply.ar)

        except Exception as exc:
            print(exc)
            response.header.rcode = getattr(dns.RCODE, 'SERVFAIL')

        return response


class DotServer(dns_server.DNSServer):
    pass


def main():
    address = ('127.0.0.1', 5001)

    upstreams = \
	[
		DotUpstream(('1.1.1.1', 853), 'cloudflare-dns.com'),
		DotUpstream(('1.0.0.1', 853), 'cloudflare-dns.com'),
		# DotUpstream(('8.8.8.8', 853), 'dns.google'),
		# DotUpstream(('9.9.9.9', 853), 'dns.quad9.net'),
	]

    resolver = DotResolver(upstreams)
    server = DotServer(resolver, *address)
    try:
        server.start()
    except (KeyboardInterrupt, SystemExit):
        pass

    server.stop()


if __name__ == '__main__':
    main()

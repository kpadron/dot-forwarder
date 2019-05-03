#!/usr/bin/env python3
import socket
import socketserver
import threading
import queue


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data, _ = self.request
        self.server.enqueue_request((data, self.client_address))

        # Could potentialy create a new thread for each new request
        # and then forward to upstream, wait for and queue response

class UdpServer(socketserver.UDPServer):
    def __init__(self, server_address, handler_class, resolver=None):
        super().__init__(server_address, handler_class)
        self.allow_reuse_address = True
        self.request_queue_size = 10
        self.request_queue = queue.Queue()
        self.response_queue = queue.Queue()

    def enqueue_request(self, request):
        self.request_queue.put(request)

    def consume_requests(self):
        while True:
            request = self.request_queue.get()

            if request is None:
                break

            self.socket.sendto(*request)

    def enqueue_response(self, response):
        pass




def main():
    address = ('127.0.0.1', 5001)

    try:
        with UdpServer(address, Handler) as server:
            request_consumer = threading.Thread(target=server.consume_requests, daemon=True)
            request_consumer.start()
            server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass

    server.enqueue_request(None)
    server.enqueue_response(None)
    request_consumer.join()
    # response_consumer.join()


if __name__ == '__main__':
    main()

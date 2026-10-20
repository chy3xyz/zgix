"""aioquic HTTP/3 client forced to an IPv4 socket (bypasses the
dual-stack IPv6 path, which intermittently drops on this host)."""
import asyncio, socket, ssl, sys
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8443
PATH = sys.argv[2] if len(sys.argv) > 2 else "/"

class H3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.status = None
        self.body = bytearray()
        self.done = asyncio.Event()

    def quic_event_received(self, event):
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                self.status = http_event.headers[0][1].decode()
                if http_event.stream_ended:
                    self.done.set()
            elif isinstance(http_event, DataReceived):
                self.body.extend(http_event.data)
                if http_event.stream_ended:
                    self.done.set()

    async def get(self, authority, path):
        stream_id = self._quic.get_next_available_stream_id()
        self.http.send_headers(stream_id, [
            (b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", authority.encode()), (b":path", path.encode()),
            (b"user-agent", b"aioquic-interop"),
        ], end_stream=True)
        self.transmit()
        await asyncio.wait_for(self.done.wait(), timeout=10)

async def main():
    loop = asyncio.get_running_loop()
    config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    config.verify_mode = ssl.CERT_NONE
    config.server_name = "localhost"
    connection = H3Client.create_quic_connection = None
    from aioquic.quic.connection import QuicConnection
    quic = QuicConnection(configuration=config)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: H3Client(quic), sock=sock)
    protocol.connect(("127.0.0.1", PORT), transmit=True)
    await protocol.wait_connected()
    await protocol.get("127.0.0.1:%d" % PORT, PATH)
    print("STATUS", protocol.status)
    print("BODY", bytes(protocol.body).decode(errors="replace"))
    protocol.close()
    await protocol.wait_closed()
    transport.close()

asyncio.run(main())

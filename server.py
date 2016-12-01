'''
Copyright 2016 Seth VanHeulen

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import argparse
import array
import hashlib
import math
import random
import sys

from Crypto.Cipher import Blowfish

from twisted.internet import reactor
from twisted.internet.protocol import Protocol, ClientFactory
from twisted.python import log
from twisted.web.http import HTTPFactory
from twisted.web.proxy import ProxyRequest, Proxy
from twisted.web.server import Site
from twisted.web.static import File


class TunnelProtocol(Protocol):
    def connectionMade(self):
        self.factory._request.channel._openTunnel(self)
        self.factory._request.transport.write(b'HTTP/1.1 200 Connection established\r\n\r\n')

    def dataReceived(self, data):
        self.factory._request.transport.write(data)


class TunnelProtocolFactory(ClientFactory):
    protocol = TunnelProtocol

    def __init__(self, request):
        self._request = request

    def clientConnectionFailed(self, connector, reason):
        self._request.setResponseCode(502, b'Bad Gateway')
        self._request.finish()


class TunnelProxyRequest(ProxyRequest):
    def process(self):
        if self.method == b'CONNECT':
            try:
                host, port = self.uri.split(b':', 1)
                host = host.decode()
                port = int(port)
            except ValueError:
                self.setResponseCode(400, b'Bad Request')
                self.finish()
            else:
                self.reactor.connectTCP(host, port, TunnelProtocolFactory(self))
        else:
            if self.uri == b'http://spector.capcom.co.jp/3ds/mhx_jp/arc/quest/q1010001.arc':
                self.uri = b'http://localhost:8081/JPN_event_encrypted.arc'
            elif self.uri == b'http://spector.capcom.co.jp/3ds/mhx_jp/arc/quest/q1020001.arc':
                self.uri = b'http://localhost:8081/JPN_challenge_encrypted.arc'
            ProxyRequest.process(self)


class TunnelProxy(Proxy):
    requestFactory = TunnelProxyRequest

    def __init__(self):
        self._tunnel = None
        Proxy.__init__(self)

    def _openTunnel(self, tunnel):
        self._tunnel = tunnel
        self._producer.resumeProducing()

    def dataReceived(self, data):
        if self._tunnel:
            self._tunnel.transport.write(data)
        else:
            Proxy.dataReceived(self, data)

    def connectionLost(self, reason):
        if self._tunnel:
            self._tunnel.transport.loseConnection()
            self._tunnel = None
        Proxy.connectionLost(self, reason)


class TunnelProxyFactory(HTTPFactory):
    protocol = TunnelProxy


def encrypt(buff, key):
    seed = random.getrandbits(32)
    buff = bytearray(buff)
    buff.extend(hashlib.sha1(buff).digest())
    xor_buff = array.array('I')
    for i in range(int(math.ceil(len(buff)/8.0))):
        xor_buff.extend([seed, i])
    xor_buff = array.array('I', Blowfish.new(key.encode()).encrypt(xor_buff.tostring()))
    xor_buff.byteswap()
    xor_buff = bytearray(xor_buff.tostring())
    for i in range(len(buff)):
        buff[i] ^= xor_buff[i]
    seed = array.array('I', [seed])
    seed.byteswap()
    return bytes(buff) + seed.tostring()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Runs a proxy server on port 8080 for installing genhax exploit quests')
    parser.add_argument('key', help='DLC encryption key')
    args = parser.parse_args()
    open('JPN_event_encrypted.arc', 'wb').write(encrypt(open('JPN_event.arc', 'rb').read(), args.key))
    open('JPN_challenge_encrypted.arc', 'wb').write(encrypt(open('JPN_challenge.arc', 'rb').read(), args.key))
    log.startLogging(sys.stderr)
    reactor.listenTCP(8080, TunnelProxyFactory())
    reactor.listenTCP(8081, Site(File('./')))
    reactor.run()


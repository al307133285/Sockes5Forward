#include "Socks5Handler.h"
// Socks5Handler.cpp
#include "Socks5Handler.h"
#include "Socks5Auth.h"
#include <QHostAddress>
#include <QLoggingCategory>
#include <QtEndian>
#include <winsock.h>
#include <QNetworkProxy>

static Q_LOGGING_CATEGORY(log, "socks5")

Socks5Handler::Socks5Handler(const QSharedPointer<QTcpSocket> client, const QSharedPointer<QNetworkProxy> proxyInfo, QObject* parent)
	: QObject(parent), m_client(client),m_proxyInfo(proxyInfo) {
	connect(m_client.get(), &QTcpSocket::readyRead, this, &Socks5Handler::onClientReadyRead);
	connect(m_client.get(), &QTcpSocket::disconnected, this, &Socks5Handler::onClientDisconnected);
	//client->setReadBufferSize(256);
	m_buffer.reserve(256);
}

Socks5Handler::~Socks5Handler() {
	qCDebug(log) << "Handler destroyed";
	
}

void Socks5Handler::onClientReadyRead() {
	if (m_state == Forwarding) {
		// 直接转发，不经过 buffer 解析
		if (m_target && m_target->state() == QAbstractSocket::ConnectedState) {
			m_target->write(m_client->readAll());
		}
		return;
	}

	m_buffer.append(m_client->readAll());

	if (m_state == Auth) {
		if (handleAuthNegotiation()) {
			if(m_state == Auth)
				m_state = Request;
		}
	}
	else if (m_state == AuthUserPass) {
		if (handleUserPassAuth()) {
			m_state = Request;
		}
	}
	else if (m_state == Request) {
		if (handleRequest()) {
			m_state = Forwarding;
		}
	}
}

bool Socks5Handler::handleAuth() {
	//if (m_buffer.size() < 2) return false;

	//quint8 ver = m_buffer[0];
	//quint8 nmethods = m_buffer[1];

	//if (ver != 0x05) {
	//	m_client->close();
	//	return false;
	//}

	//if (m_buffer.size() < 2 + nmethods) return false;

	//bool hasNoAuth = false;
	//bool hasUserPass = false;

	//for (int i = 0; i < nmethods; ++i) {
	//	quint8 method = static_cast<quint8>(m_buffer[2 + i]);
	//	if (method == NoAuth) hasNoAuth = true;
	//	if (method == UserPass) hasUserPass = true;
	//}

	//m_buffer.remove(0, 2 + nmethods);

	//// 选择认证方式
	//if (Socks5Auth::isEnabled() && hasUserPass) {
	//	m_client->write(QByteArray::fromHex("0502")); // VER=5, METHOD=UserPass
	//	m_authenticated = false;
	//	return true;
	//}
	//else if (!Socks5Auth::isEnabled() && hasNoAuth) {
	//	m_client->write(QByteArray::fromHex("0500")); // VER=5, METHOD=NoAuth
	//	m_authenticated = true;
	//	return true;
	//}
	//else {
	//	m_client->write(QByteArray::fromHex("05ff")); // No acceptable methods
	//	m_client->close();
	//	return false;
	//}
	return true;
}

void Socks5Handler::onClientDisconnected() {
	deleteLater();
}

void Socks5Handler::onTargetConnected() {
	QHostAddress bindAddr = m_target->localAddress();
	if (bindAddr.protocol() == QAbstractSocket::IPv6Protocol)
		bindAddr = QHostAddress::LocalHostIPv6;
	else
		bindAddr = QHostAddress::LocalHost;

	sendReply(0x00, bindAddr, m_target->localPort());
}
void Socks5Handler::onProxyChanged() {
	m_client->close();
}
void Socks5Handler::onTargetReadyRead() {
	m_client->write(m_target->readAll());
}

void Socks5Handler::onTargetDisconnected() {
	m_client->close();
}

void Socks5Handler::onTargetError(const QAbstractSocket::SocketError socketError)
{
	sendReply(0x01, QHostAddress::LocalHost, 0);
	m_client->close();
}

void Socks5Handler::sendReply(quint8 reply, const QHostAddress& addr, quint16 port) {
	QByteArray resp;
	resp.append(char(0x05)); // VER
	resp.append(char(reply));
	resp.append(char(0x00)); // RSV

	if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
		resp.append(char(0x01));
		quint32 ipv4 = addr.toIPv4Address();

		resp.append(static_cast<char>(ipv4 >> 24));
		resp.append(static_cast<char>(ipv4 >> 16));
		resp.append(static_cast<char>(ipv4 >> 8));
		resp.append(static_cast<char>(ipv4));
	}
	else if (addr.protocol() == QAbstractSocket::IPv6Protocol) {
		resp.append(char(0x04));
		Q_IPV6ADDR ipv6 = addr.toIPv6Address();
		resp.append(reinterpret_cast<const char*>(ipv6.c), 16);
		
	}
	else {
		resp.append(char(0x03));
		QByteArray domain = addr.toString().toLatin1();
		resp.append(char(domain.size()));
		resp.append(domain);
	}

	resp.append(static_cast<char>(port >> 8));
	resp.append(static_cast<char>(port & 0xFF));

	m_client->write(resp);
}

bool Socks5Handler::handleRequest() {
	if (m_buffer.size() < 4) return false;

	quint8 ver = m_buffer[0];
	quint8 cmd = m_buffer[1];
	// RSV = m_buffer[2]
	quint8 atyp = m_buffer[3];

	if (ver != 0x05 || !m_authenticated) {
		sendReply(0x01, QHostAddress::LocalHost, 0); // General failure
		m_client->close();
		return false;
	}

	int addrLen = 0;
	if (atyp == 0x01) {
		addrLen = 4; // IPv4
	}
	else if (atyp == 0x04) {
		addrLen = 16; // IPv6
	}
	else if (atyp == 0x03) {
		if (m_buffer.size() < 5) return false;
		addrLen = 1 + static_cast<quint8>(m_buffer[4]); // domain length + data
	}
	else {
		sendReply(0x08, QHostAddress::LocalHost, 0); // Address type not supported
		m_client->close();
		return false;
	}

	if (m_buffer.size() < 4 + addrLen + 2) return false;

	QByteArray addrBytes = m_buffer.mid(4, addrLen);
	quint16 port = (static_cast<quint8>(m_buffer[4 + addrLen]) << 8) |
		static_cast<quint8>(m_buffer[5 + addrLen]);

	QString targetHost;
	if (atyp == 0x01) {
		quint32 ip = qFromBigEndian(*reinterpret_cast<const quint32*>(addrBytes.constData()));
		targetHost = QHostAddress(ip).toString();
	}
	else if (atyp == 0x04) {
		Q_IPV6ADDR ipv6;
		memcpy(ipv6.c, addrBytes.constData(), 16);
		targetHost = QHostAddress(ipv6).toString();
	}
	else if (atyp == 0x03) {
		targetHost = QString::fromLatin1(addrBytes.mid(1));
	}

	m_buffer.clear();

	if (cmd == Connect) {		
		m_target.reset(new QTcpSocket(this));
		//m_target->setReadBufferSize(256);
		//QNetworkProxy proxy(QNetworkProxy::Socks5Proxy, "192.168.100.1",50001,"al","song0327");
		if (m_proxyInfo) {
			m_target->setProxy(*m_proxyInfo.get());
		}

		connect(m_target.get(), &QTcpSocket::connected, this, &Socks5Handler::onTargetConnected);
		connect(m_target.get(), &QTcpSocket::readyRead, this, &Socks5Handler::onTargetReadyRead);
		connect(m_target.get(), &QTcpSocket::disconnected, this, &Socks5Handler::onTargetDisconnected);
		connect(m_target.get(), &QTcpSocket::errorOccurred, this, &Socks5Handler::onTargetError);
		
		m_target->connectToHost(targetHost, port);
		return true;

	}
	else if (cmd == UdpAssociate) {
		startUdpRelay(m_client->peerAddress(), m_client->peerPort());
		return true;

	}
	else {
		sendReply(0x07, QHostAddress::LocalHost, 0); // Command not supported
		m_client->close();
		return false;
	}
}

void Socks5Handler::startUdpRelay(const QHostAddress& clientAddr, quint16 clientPort) {
	m_udpSocket.reset(new QUdpSocket(this));
	if (!m_udpSocket->bind(QHostAddress::Any, 0)) {
		sendReply(0x01, QHostAddress::LocalHost, 0);
		m_client->close();
		return;
	}

	connect(m_udpSocket.get(), &QUdpSocket::readyRead, this, &Socks5Handler::onUdpSocketReady);

	QHostAddress bindAddr = m_udpSocket->localAddress();
	if (bindAddr.protocol() == QAbstractSocket::IPv6Protocol)
		bindAddr = QHostAddress::LocalHostIPv6;
	else
		bindAddr = QHostAddress::LocalHost;

	sendReply(0x00, bindAddr, m_udpSocket->localPort());
}

void Socks5Handler::onUdpSocketReady() {
	// 简化：仅转发，不解析 SOCKS5 UDP 包头（实际需解析）
	while (m_udpSocket->hasPendingDatagrams()) {
		QByteArray datagram;
		datagram.resize(m_udpSocket->pendingDatagramSize());
		QHostAddress sender;
		quint16 senderPort;
		m_udpSocket->readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);

		// 这里应解析 SOCKS5 UDP 请求包（含FRAG、ATYP等），此处简化为直通
		// 实际使用时需按 RFC 1928 第7节解析

		// 回写给客户端（简化）
		m_udpSocket->writeDatagram(datagram, m_client->peerAddress(), m_client->peerPort());
	}
}

bool Socks5Handler::handleAuthNegotiation() {
	if (m_buffer.size() < 2) return false;

	quint8 ver = m_buffer[0];
	quint8 nmethods = m_buffer[1];

	if (ver != 0x05) {
		m_client->close();
		return false;
	}

	if (m_buffer.size() < 2 + nmethods) return false;

	bool hasNoAuth = false;
	bool hasUserPass = false;
	for (int i = 0; i < nmethods; ++i) {
		quint8 method = static_cast<quint8>(m_buffer[2 + i]);
		if (method == 0x00) hasNoAuth = true;
		if (method == 0x02) hasUserPass = true;
	}

	m_buffer.remove(0, 2 + nmethods);

	auto* auth = Socks5Auth::instance();
	if (auth->isEnabled() && hasUserPass) {
		m_client->write(QByteArray::fromHex("0502"));
		m_state = AuthUserPass; // 下一步：等用户名/密码
		return true;
	}
	else if (!auth->isEnabled() && hasNoAuth) {
		m_client->write(QByteArray::fromHex("0500"));
		m_authenticated = true;
		return true;
	}
	else {
		m_client->write(QByteArray::fromHex("05ff"));
		m_client->close();
		return false;
	}
}

bool Socks5Handler::handleUserPassAuth() {
	if (m_buffer.size() < 2) return false;

	quint8 ver = m_buffer[0];
	if (ver != 0x01) { // RFC 1929: version must be 0x01
		m_client->close();
		return false;
	}

	quint8 ulen = static_cast<quint8>(m_buffer[1]);
	if (m_buffer.size() < 2 + ulen + 1) return false;

	QString username = QString::fromLatin1(m_buffer.mid(2, ulen));
	quint8 plen = static_cast<quint8>(m_buffer[2 + ulen]);
	if (m_buffer.size() < 2 + ulen + 1 + plen) return false;

	QString password = QString::fromLatin1(m_buffer.mid(2 + ulen + 1, plen));

	m_buffer.clear();

	if (Socks5Auth::instance()->verify(username, password)) {
		m_client->write(QByteArray::fromHex("0100")); // VER=1, STATUS=0 (success)
		m_authenticated = true;
		return true;
	}
	else {
		m_client->write(QByteArray::fromHex("0101")); // STATUS=1 (failure)
		m_client->close();
		return false;
	}
}
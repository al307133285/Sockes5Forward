#include "Socks5Server.h"
#include "Socks5Server.h"
#include "Socks5Handler.h"

Socks5Server::Socks5Server(const quint16 port, const QSharedPointer<QNetworkProxy> proxyInfo, QObject* parent)
	: QObject(parent), m_port(port),m_proxyInfo(proxyInfo) {
}

bool Socks5Server::start() {
	m_server.reset( new QTcpServer(this));
	if (!m_server->listen(QHostAddress::LocalHost, m_port)) {
		emit error(m_server->errorString());
		return false;
	}
	connect(m_server.get(), &QTcpServer::newConnection, this, &Socks5Server::onNewConnection);
	emit started(m_server->serverPort());
	return true;
}

void Socks5Server::stop() {
	if (m_server) m_server->close();
}

quint16 Socks5Server::port()
{
	if (!m_server || !m_server->isListening())
		return 0;
	return m_server->serverPort();
}

void Socks5Server::changePorxy(const QSharedPointer<QNetworkProxy> proxyInfo)
{
	m_proxyInfo = proxyInfo;
	emit proxyChanged();

}

void Socks5Server::onNewConnection() {
	while (m_server->hasPendingConnections()) {
		qDebug() << "onNewConnection";
		QSharedPointer<QTcpSocket>client( m_server->nextPendingConnection());
		auto handler= new Socks5Handler(client, m_proxyInfo,this); // 自动内存管理
		connect(this, &Socks5Server::proxyChanged, handler, &Socks5Handler::onProxyChanged);
	}
}
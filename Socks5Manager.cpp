#include "Socks5Manager.h"
#include <QMutexLocker>
Socks5Manager* Socks5Manager::getInstance()
{
    static Socks5Manager self;
    return &self;
}

QString Socks5Manager::openProxy(quint16& port, const QSharedPointer<QNetworkProxy> proxyInfo)
{
    QMutexLocker lock(&m_mutex);
    if (m_socks5Servers.contains(port))
        return "";
    QSharedPointer<Socks5Server> server(new Socks5Server(port, proxyInfo));
    if (!server->start()) {
        return "";
    }
    port = server->port();

    m_socks5Servers[port] = server;
    
    return QString("socks5://127.0.0.1:%1").arg(port);
}

bool Socks5Manager::changePorxy(const quint16 port, const QSharedPointer<QNetworkProxy> proxyInfo)
{
    QMutexLocker lock(&m_mutex);
	if (!m_socks5Servers.contains(port))
		return false;
    m_socks5Servers[port]->changePorxy(proxyInfo);

    return true;
}

bool Socks5Manager::closeProxy(const quint16 port)
{
	QMutexLocker lock(&m_mutex);
	if (!m_socks5Servers.contains(port))
		return false;
    m_socks5Servers[port]->stop();
    m_socks5Servers.remove(port);
	return true;
}

Socks5Manager::~Socks5Manager()
{
    closeAllProxy();
}

void Socks5Manager::closeAllProxy()
{
    QMutexLocker lock(&m_mutex);
    for (const auto& item : m_socks5Servers) {
        item->stop();
    }
}

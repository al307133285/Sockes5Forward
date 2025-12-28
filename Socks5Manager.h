#pragma once
#include <QString>
#include <QSharedPointer>
#include <QNetworkProxy>
#include <QMutex>
#include "Socks5Server.h"
class Socks5Manager
{
public:
	static Socks5Manager* getInstance();
	QString openProxy(quint16& port, const QSharedPointer<QNetworkProxy> proxyInfo);
	bool changePorxy(const quint16 port, const QSharedPointer<QNetworkProxy> proxyInfo);
	bool closeProxy(const quint16 port);
	~Socks5Manager();

private:
	void closeAllProxy();
	Socks5Manager() = default;
private:
	QMutex m_mutex;
	QMap<quint16, QSharedPointer<Socks5Server>> m_socks5Servers;

};


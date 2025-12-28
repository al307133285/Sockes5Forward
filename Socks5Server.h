#pragma once
#include <QObject>
#include <QTcpServer>
#include <QSharedPointer>
class Socks5Server : public QObject
{
	Q_OBJECT
public:
	explicit Socks5Server(const quint16 port, const QSharedPointer<QNetworkProxy> proxyInfo = nullptr, QObject* parent = nullptr);
	bool start();
	void stop();
	quint16 port();
	void changePorxy(const QSharedPointer<QNetworkProxy> proxyInfo);
	quint16 port() const { return m_port; }

signals:
	void started(quint16 port);
	void error(QString msg);
	void proxyChanged();

private slots:
	void onNewConnection();

private:
	QSharedPointer<QTcpServer> m_server = Q_NULLPTR;
	QSharedPointer<QNetworkProxy> m_proxyInfo = Q_NULLPTR;
	quint16 m_port = 0;
};


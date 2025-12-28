#pragma once
#include "GlobalDefine.h"
#include "proxy.h"
class Socks5Api
{
public:
	static Socks5Api* getInstance();
	bool initServer();


	QString openProxy(quint16& port, const QSharedPointer<Proxy> proxInfo);
	bool changeProxy(const quint16 port, const QSharedPointer<Proxy> proxInfo);
	bool closeProxy(const quint16 port);
private:
	Socks5Api();
	QJsonObject request(const QString& path, const QJsonObject& json);



private:
	bool m_isInitSuccess = false;
	QWaitCondition m_waitConditon;
	QMutex m_mutex;
	QSemaphore m_semaphore{1};
	QString m_apiUrl;
	QProcess m_process;
};


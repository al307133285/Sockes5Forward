#pragma once
#include <QObject>
#include <QTcpSocket>
#include <QUdpSocket>

class Socks5Handler : public QObject {
	Q_OBJECT
public:
	explicit Socks5Handler(const QSharedPointer<QTcpSocket> client, const QSharedPointer<QNetworkProxy> proxyInfo, QObject* parent = nullptr);
	~Socks5Handler();


public slots:
	void onProxyChanged();
private slots:
	void onClientReadyRead();
	void onTargetConnected();
	void onTargetReadyRead();
	void onClientDisconnected();
	void onTargetDisconnected();
	void onTargetError(const QAbstractSocket::SocketError socketError);

	void onUdpSocketReady();

private:
	enum State { Auth, AuthUserPass, Request, Forwarding };
	enum AuthMethod { NoAuth = 0x00, UserPass = 0x02, NoAcceptable = 0xFF };
	enum Command { Connect = 0x01, Bind = 0x02, UdpAssociate = 0x03 };

	bool handleAuthNegotiation();
	bool handleUserPassAuth();
	bool handleAuth();
	bool handleRequest();
	void sendReply(quint8 reply, const QHostAddress& addr, quint16 port);
	void startUdpRelay(const QHostAddress& clientAddr, quint16 clientPort);


	QSharedPointer<QNetworkProxy> m_proxyInfo = nullptr;
	QSharedPointer<QTcpSocket>m_client = nullptr;
	QSharedPointer<QTcpSocket> m_target = nullptr;
	QSharedPointer<QUdpSocket> m_udpSocket = nullptr;
	State m_state = Auth;
	bool m_authenticated = false;
	QByteArray m_buffer;

	
};

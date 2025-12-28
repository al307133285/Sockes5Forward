#include "Socks5Api.h"
#include "UtilTools.h"
Socks5Api* Socks5Api::getInstance()
{
	static Socks5Api self;

	return &self;
	
}

bool Socks5Api::initServer()
{
	if (m_semaphore.tryAcquire()) {
		if (m_process.state() == QProcess::Running) {
			GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, m_process.processId());
			UtilTools::sleep(2000);
		}
		
		m_process.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* args) {
			qDebug() << args->flags;
			args->flags |= CREATE_NEW_PROCESS_GROUP;
			});

		quint16 port = UtilTools::getunUsePort();
		QString path = QString(R"(%1/Socks5Server.exe)").arg(QCoreApplication::applicationDirPath());

		QStringList params;
		params << "-port" << QString::number(port);

		m_process.start(path, params);
		if (!m_process.waitForStarted()) {
			QMutexLocker lock(&m_mutex);
			m_waitConditon.wakeAll();
			return false;
		}

		m_apiUrl = QString(R"(http://127.0.0.1:%1/)").arg(port);
		qDebug() << m_apiUrl;
		QMutexLocker lock(&m_mutex);
		m_waitConditon.wakeAll();
		return true;
	}
	else {
		QMutexLocker lock(&m_mutex);
		m_waitConditon.wait(&m_mutex);
	}	
	
	return false;
}

Socks5Api::Socks5Api()
{
	m_process.setProcessChannelMode(QProcess::ProcessChannelMode::MergedChannels);

	CkGlobal global;
	global.UnlockBundle("VZHZFY.CBX082025_I77F9GD0CJ11");
	if (global.get_UnlockStatus() < 2)
		m_isInitSuccess = false;
	global.put_DefaultUtf8(true);
	m_isInitSuccess =  true;



}

QJsonObject Socks5Api::request(const QString& path, const QJsonObject& json)
{
	QString postData = QJsonDocument(json).toJson(QJsonDocument::Compact);
	qDebug() << "request:" << postData;	
	
	CkHttpResponse resp;
	CkHttp http;
	QString url = m_apiUrl + path;

	if (!http.HttpStr("POST", url.toUtf8(), postData.toUtf8(), "utf-8", "application/json", resp)) {
		initServer();
		return {};
	}
	postData = QString::fromUtf8(resp.bodyStr());

	qDebug() << "request:" << postData;

	if (resp.get_StatusCode() != 200) {

		return {};
	}

	return QJsonDocument::fromJson(postData.toUtf8()).object();;
}

QString Socks5Api::openProxy(quint16& port, const QSharedPointer<Proxy> proxInfo)
{
	if (!proxInfo)
		return "";

	QJsonObject json;

	json["localPort"] = port;
	json["proxyHost"] = proxInfo->getAddress();
	json["proxyPort"] = proxInfo->getPort();
	json["proxyUser"] = proxInfo->getUser(false);
	json["proxyPasswd"] = proxInfo->getPasswd(false);

	if (proxInfo->getProxyType() == Proxy::ProxyType::Socks5) {
		json["proxyType"] = 0;
	}
	else {
		json["proxyType"] = 1;
	}

	QJsonObject resutlJson = request(__func__,json);

	if (!resutlJson.contains("status") || !resutlJson["status"].toBool())
		return "";

	resutlJson = resutlJson["data"].toObject();
	if (!resutlJson.contains("localUrl"))
		return "";
	port = resutlJson["localPort"].toInt();

	return resutlJson["localUrl"].toString();
}

bool Socks5Api::changeProxy(const quint16 port, const QSharedPointer<Proxy> proxInfo)
{
	if (!proxInfo)
		return false;

	QJsonObject json;

	json["localPort"] = port;
	json["proxyHost"] = proxInfo->getAddress();
	json["proxyPort"] = proxInfo->getPort();
	json["proxyUser"] = proxInfo->getUser(false);
	json["proxyPasswd"] = proxInfo->getPasswd(false);

	if (proxInfo->getProxyType() == Proxy::ProxyType::Socks5) {
		json["proxyType"] = 0;
	}
	else {
		json["proxyType"] = 1;
	}

	QJsonObject resutlJson = request(__func__, json);

	if (!resutlJson.contains("status") || !resutlJson["status"].toBool())
		return false;

	return true;
}

bool Socks5Api::closeProxy(const quint16 port)
{

	QJsonObject json;

	json["localPort"] = port;

	QJsonObject resutlJson = request(__func__, json);

	if (!resutlJson.contains("status") || !resutlJson["status"].toBool())
		return false;

	return true;
}

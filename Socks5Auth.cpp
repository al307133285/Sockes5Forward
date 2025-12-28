// Socks5Auth.cpp
#include "Socks5Auth.h"
#include <QSettings>
#include <QLoggingCategory>
#include <QCryptographicHash>

static Q_LOGGING_CATEGORY(authLog, "socks5.auth")

// 单例
Socks5Auth* Socks5Auth::instance() {
	static Socks5Auth inst;
	return &inst;
}

void Socks5Auth::setEnabled(bool enabled) {
	QMutexLocker locker(&m_mutex);
	m_enabled = enabled;
}

bool Socks5Auth::isEnabled() const {
	QMutexLocker locker(&m_mutex);
	return m_enabled;
}

void Socks5Auth::addUser(const QString& username, const QString& password) {
	if (username.isEmpty()) return;
	QMutexLocker locker(&m_mutex);
	m_users[username] = password; // 明文存储（生产环境建议哈希）
}

void Socks5Auth::removeUser(const QString& username) {
	QMutexLocker locker(&m_mutex);
	m_users.remove(username);
}

void Socks5Auth::clearUsers() {
	QMutexLocker locker(&m_mutex);
	m_users.clear();
}

bool Socks5Auth::hasUser(const QString& username) const {
	QMutexLocker locker(&m_mutex);
	return m_users.contains(username);
}

int Socks5Auth::userCount() const {
	QMutexLocker locker(&m_mutex);
	return m_users.size();
}

void Socks5Auth::setVerifyCallback(VerifyCallback callback) {
	QMutexLocker locker(&m_mutex);
	m_verifyCallback = std::move(callback);
}

bool Socks5Auth::verify(const QString& username, const QString& password) const {
	if (!isEnabled()) return true; // 未启用则视为通过

	QMutexLocker locker(&m_mutex);

	// 1. 优先使用自定义回调
	if (m_verifyCallback) {
		bool ok = m_verifyCallback(username, password);
		qCInfo(authLog) << "Custom auth:" << username << "->" << (ok ? "OK" : "FAIL");
		return ok;
	}

	// 2. 使用内置用户表
	auto it = m_users.find(username);
	if (it != m_users.end()) {
		bool ok = (it.value() == password);
		qCInfo(authLog) << "Built-in auth:" << username << "->" << (ok ? "OK" : "FAIL");
		return ok;
	}

	qCWarning(authLog) << "Auth failed: unknown user" << username;
	return false;
}

void Socks5Auth::loadFromSettings(QSettings& settings) {
	QMutexLocker locker(&m_mutex);
	m_users.clear();
	const QStringList keys = settings.childKeys();
	for (const QString& key : keys) {
		if (key.startsWith("auth/")) {
			QString user = key.mid(5); // skip "auth/"
			QString pass = settings.value(key).toString();
			m_users[user] = pass;
		}
	}
	m_enabled = !m_users.isEmpty();
	qCInfo(authLog) << "Loaded" << m_users.size() << "users from settings";
}

void Socks5Auth::saveToSettings(QSettings& settings) const {
	QMutexLocker locker(&m_mutex);
	// 先清除旧的
	const QStringList keys = settings.childKeys();
	for (const QString& key : keys) {
		if (key.startsWith("auth/")) {
			settings.remove(key);
		}
	}
	// 保存新的
	for (auto it = m_users.constBegin(); it != m_users.constEnd(); ++it) {
		settings.setValue("auth/" + it.key(), it.value());
	}
	qCInfo(authLog) << "Saved" << m_users.size() << "users to settings";
}
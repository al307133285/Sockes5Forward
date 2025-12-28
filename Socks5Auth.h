// Socks5Auth.h
#pragma once
#include <QString>
#include <QMap>
#include <QMutex>
#include <functional>

class Socks5Auth {
public:
	using VerifyCallback = std::function<bool(const QString&, const QString&)>;

	// 单例访问
	static Socks5Auth* instance();

	// 启用/禁用认证
	void setEnabled(bool enabled);
	bool isEnabled() const;

	// 内置用户管理
	void addUser(const QString& username, const QString& password);
	void removeUser(const QString& username);
	void clearUsers();
	bool hasUser(const QString& username) const;
	int userCount() const;

	// 自定义验证回调（优先级高于内置用户表）
	void setVerifyCallback(VerifyCallback callback);
	bool verify(const QString& username, const QString& password) const;

	// 从 QSettings 加载（格式：auth/user1=password1）
	void loadFromSettings(class QSettings& settings);
	void saveToSettings(class QSettings& settings) const;

private:
	Socks5Auth() = default;
	mutable QMutex m_mutex;
	QMap<QString, QString> m_users;
	VerifyCallback m_verifyCallback;
	bool m_enabled = false;
};
#ifndef CONFIG_H
#define CONFIG_H

// Honeypot Configuration
#define HONEYPOT_VERSION "1.2.0"

// Network Configuration
#define MAX_LISTENING_PORTS 6
#define MAX_CONCURRENT_CONNECTIONS 6
#define CONNECTION_TIMEOUT_MS 10000
#define RATE_LIMIT_WINDOW_MS 60000
#define RATE_LIMIT_MAX_CONNECTIONS 10

// Logging Configuration
#define LOG_BUFFER_SIZE 4096
#define MAX_PAYLOAD_SIZE 1024
#define FLASH_LOG_SIZE 16384  // 16KB for log storage
#define MAX_LOG_ENTRIES 100

// Service Banners
#define FTP_BANNER "220 FTP Server Ready\r\n"
#define TELNET_BANNER "\r\nWelcome to Device Login\r\n\r\n"
#define MQTT_BANNER_CONNACK "\x20\x02\x00\x05"  // CONNACK, Not authorized

// WiFi Configuration (to be set via menuconfig)
#ifndef CONFIG_WIFI_SSID
#define CONFIG_WIFI_SSID "IoT-Honeypot"
#endif

#ifndef CONFIG_WIFI_PASSWORD
#define CONFIG_WIFI_PASSWORD "securepassword123"
#endif

// Remote Logging Configuration
#ifdef CONFIG_ENABLE_REMOTE_LOGGING
#define REMOTE_SERVER_URL "https://logs.yourdomain.com/api/collect"
#define REMOTE_UPLOAD_INTERVAL_MS 300000  // 5 minutes
#endif

#endif // CONFIG_H
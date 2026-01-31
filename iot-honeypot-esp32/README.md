# IoT Honeypot for ESP32-WROOM-32D

A professional-grade, lightweight IoT honeypot designed for passive monitoring of real-world attacks targeting common IoT services.

## 📋 Overview

This honeypot simulates vulnerable IoT services to attract and monitor attack traffic, providing valuable threat intelligence without exposing real systems to risk. Built specifically for the ESP32-WROOM-32D microcontroller, it's optimized for stability and minimal resource usage.

## ✨ Features

- **Multi-service simulation**: HTTP, Telnet, FTP, and MQTT on standard ports
- **Passive monitoring**: No command execution or traffic forwarding
- **Comprehensive logging**: IP addresses, credentials, payload hashes, timestamps
- **Resource protection**: Rate limiting, connection limits, watchdog timer
- **Remote logging**: Optional HTTP-based log upload to remote server
- **Stable operation**: FreeRTOS-based with single-task select() multiplexing

## 🛠️ Hardware Requirements

- ESP32-WROOM-32D development board
- USB cable for programming and power
- WiFi network with internet access (for remote logging)

## 📦 Installation

### 1. Prerequisites

```bash
# Install ESP-IDF (v5.0 or later)
git clone -b v5.1.2 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh
source export.sh
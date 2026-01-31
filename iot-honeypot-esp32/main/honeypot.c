/*
 * IoT Honeypot - Core Implementation
 * 
 * Author: Alex Chen
 * Created: 2023-10-15
 * Updated: 2024-01-20
 * 
 * Core honeypot logic with FreeRTOS task management
 */

#include "honeypot.h"
#include "networking/socket_manager.h"
#include "services/http_service.h"
#include "services/telnet_service.h"
#include "services/ftp_service.h"
#include "services/mqtt_service.h"
#include "logging/attack_logger.h"
#include "security/rate_limiter.h"
#include "utils/helpers.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <string.h>

static const char *TAG = "honeypot";

// Honeypot state
static honeypot_config_t current_config = {
    .ports = {80, 23, 21, 1883, 8080, 2323},
    .port_count = 6,
    .max_connections = MAX_CONCURRENT_CONNECTIONS,
    .connection_timeout_ms = CONNECTION_TIMEOUT_MS,
    .enable_logging = true,
    .enable_remote_upload = false
};

static honeypot_stats_t stats = {0};
static TaskHandle_t honeypot_task_handle = NULL;
static bool honeypot_running = false;

// Internal function prototypes
static void honeypot_task(void *pvParameters);
static void handle_incoming_connection(int sock_fd, uint16_t port, struct sockaddr_in *client_addr);
static void cleanup_stale_connections(void);
static void update_statistics(uint16_t port);

esp_err_t honeypot_init(void)
{
    ESP_LOGI(TAG, "Initializing honeypot");
    
    // Initialize attack logger
    if (attack_logger_init() != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize attack logger");
        return ESP_FAIL;
    }
    
    // Initialize rate limiter
    if (rate_limiter_init() != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize rate limiter");
        return ESP_FAIL;
    }
    
    // Initialize services
    http_service_init();
    telnet_service_init();
    ftp_service_init();
    mqtt_service_init();
    
    stats.start_time = time(NULL);
    
    ESP_LOGI(TAG, "Honeypot initialized successfully");
    return ESP_OK;
}

esp_err_t honeypot_start(void)
{
    if (honeypot_running) {
        ESP_LOGW(TAG, "Honeypot already running");
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "Starting honeypot task");
    
    // Create honeypot task
    BaseType_t result = xTaskCreate(
        honeypot_task,
        "honeypot_task",
        8192,
        NULL,
        5,
        &honeypot_task_handle
    );
    
    if (result != pdPASS) {
        ESP_LOGE(TAG, "Failed to create honeypot task");
        return ESP_FAIL;
    }
    
    honeypot_running = true;
    ESP_LOGI(TAG, "Honeypot started successfully");
    return ESP_OK;
}

esp_err_t honeypot_stop(void)
{
    if (!honeypot_running) {
        ESP_LOGW(TAG, "Honeypot not running");
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "Stopping honeypot");
    honeypot_running = false;
    
    if (honeypot_task_handle != NULL) {
        vTaskDelete(honeypot_task_handle);
        honeypot_task_handle = NULL;
    }
    
    // Close all listening sockets
    socket_manager_close_all();
    
    ESP_LOGI(TAG, "Honeypot stopped");
    return ESP_OK;
}

esp_err_t honeypot_get_stats(honeypot_stats_t *out_stats)
{
    if (out_stats == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    memcpy(out_stats, &stats, sizeof(honeypot_stats_t));
    return ESP_OK;
}

esp_err_t honeypot_reset_stats(void)
{
    ESP_LOGI(TAG, "Resetting statistics");
    memset(&stats, 0, sizeof(stats));
    stats.start_time = time(NULL);
    return ESP_OK;
}

esp_err_t honeypot_set_config(const honeypot_config_t *config)
{
    if (config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    memcpy(&current_config, config, sizeof(honeypot_config_t));
    ESP_LOGI(TAG, "Configuration updated");
    return ESP_OK;
}

esp_err_t honeypot_get_config(honeypot_config_t *config)
{
    if (config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    memcpy(config, &current_config, sizeof(honeypot_config_t));
    return ESP_OK;
}

static void honeypot_task(void *pvParameters)
{
    ESP_LOGI(TAG, "Honeypot task started");
    
    // Create listening sockets for all configured ports
    for (int i = 0; i < current_config.port_count; i++) {
        if (socket_manager_create_listener(current_config.ports[i]) != ESP_OK) {
            ESP_LOGE(TAG, "Failed to create listener for port %d", current_config.ports[i]);
        }
    }
    
    fd_set read_fds;
    struct timeval timeout;
    
    while (honeypot_running) {
        // Setup select() timeout
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        // Get file descriptor set from socket manager
        if (!socket_manager_get_fd_set(&read_fds)) {
            vTaskDelay(100 / portTICK_PERIOD_MS);
            continue;
        }
        
        // Wait for socket activity
        int activity = select(FD_SETSIZE, &read_fds, NULL, NULL, &timeout);
        
        if (activity < 0 && errno != EINTR) {
            ESP_LOGE(TAG, "select() error: %d", errno);
            vTaskDelay(100 / portTICK_PERIOD_MS);
            continue;
        }
        
        if (activity > 0) {
            // Check for new connections on each port
            for (int i = 0; i < current_config.port_count; i++) {
                int sock_fd = socket_manager_get_listener_fd(current_config.ports[i]);
                if (sock_fd >= 0 && FD_ISSET(sock_fd, &read_fds)) {
                    struct sockaddr_in client_addr;
                    socklen_t addr_len = sizeof(client_addr);
                    
                    int client_fd = accept(sock_fd, (struct sockaddr *)&client_addr, &addr_len);
                    if (client_fd >= 0) {
                        handle_incoming_connection(client_fd, current_config.ports[i], &client_addr);
                    }
                }
            }
            
            // Handle data on existing connections
            socket_manager_handle_connections(&read_fds);
        }
        
        // Cleanup stale connections periodically
        static TickType_t last_cleanup = 0;
        TickType_t now = xTaskGetTickCount();
        if (now - last_cleanup > pdMS_TO_TICKS(5000)) {
            cleanup_stale_connections();
            last_cleanup = now;
        }
        
        // Feed the watchdog
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }
    
    ESP_LOGI(TAG, "Honeypot task exiting");
    vTaskDelete(NULL);
}

static void handle_incoming_connection(int sock_fd, uint16_t port, struct sockaddr_in *client_addr)
{
    char client_ip[16];
    inet_ntoa_r(client_addr->sin_addr, client_ip, sizeof(client_ip) - 1);
    
    // Check rate limit
    if (!rate_limiter_check(client_ip)) {
        ESP_LOGW(TAG, "Rate limiting connection from %s", client_ip);
        close(sock_fd);
        stats.rate_limited++;
        return;
    }
    
    // Check max connections
    if (!socket_manager_can_accept_connection()) {
        ESP_LOGW(TAG, "Max connections reached, rejecting %s", client_ip);
        close(sock_fd);
        return;
    }
    
    // Add connection to socket manager
    if (socket_manager_add_connection(sock_fd, port, client_addr) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to add connection from %s", client_ip);
        close(sock_fd);
        return;
    }
    
    stats.total_connections++;
    ESP_LOGI(TAG, "New connection from %s on port %d", client_ip, port);
}

static void cleanup_stale_connections(void)
{
    int cleaned = socket_manager_cleanup_stale_connections(current_config.connection_timeout_ms);
    if (cleaned > 0) {
        ESP_LOGI(TAG, "Cleaned up %d stale connections", cleaned);
    }
}

static void update_statistics(uint16_t port)
{
    stats.attacks_logged++;
    
    switch (port) {
        case 80:
        case 8080:
            stats.http_attacks++;
            break;
        case 23:
        case 2323:
            stats.telnet_attacks++;
            break;
        case 21:
            stats.ftp_attacks++;
            break;
        case 1883:
            stats.mqtt_attacks++;
            break;
    }
}
/*
 * Attack Logger - Centralized logging system
 * 
 * Author: James Wilson
 * Created: 2023-10-20
 * Updated: 2024-01-18
 * 
 * Handles attack logging with buffer management and flash storage
 */

#include "attack_logger.h"
#include "flash_storage.h"
#include "utils/helpers.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <string.h>
#include <time.h>

static const char *TAG = "attack_logger";

// Circular buffer for logs
static attack_log_t log_buffer[MAX_LOG_ENTRIES];
static size_t buffer_head = 0;
static size_t buffer_tail = 0;
static size_t buffer_count = 0;

// Statistics
static logger_stats_t stats = {0};

esp_err_t attack_logger_init(void)
{
    ESP_LOGI(TAG, "Initializing attack logger");
    
    // Initialize flash storage
    if (flash_storage_init() != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize flash storage");
        return ESP_FAIL;
    }
    
    // Load existing logs from flash
    size_t loaded = flash_storage_load_logs(log_buffer, MAX_LOG_ENTRIES);
    if (loaded > 0) {
        buffer_head = loaded % MAX_LOG_ENTRIES;
        buffer_count = loaded;
        ESP_LOGI(TAG, "Loaded %d logs from flash", loaded);
    }
    
    stats.start_time = time(NULL);
    ESP_LOGI(TAG, "Attack logger initialized");
    
    return ESP_OK;
}

esp_err_t attack_logger_log(const attack_log_t *log_entry)
{
    if (log_entry == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    // Add to circular buffer
    memcpy(&log_buffer[buffer_head], log_entry, sizeof(attack_log_t));
    buffer_head = (buffer_head + 1) % MAX_LOG_ENTRIES;
    
    if (buffer_count < MAX_LOG_ENTRIES) {
        buffer_count++;
    } else {
        buffer_tail = (buffer_tail + 1) % MAX_LOG_ENTRIES;
    }
    
    // Update statistics
    stats.total_logged++;
    stats.last_log_time = time(NULL);
    
    // Save to flash
    flash_storage_save_log(log_entry);
    
    // Log to console for debugging
    log_to_console(log_entry);
    
    return ESP_OK;
}

esp_err_t attack_logger_get_recent(attack_log_t *logs, size_t max_logs, size_t *num_logs)
{
    if (logs == NULL || num_logs == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    size_t count = buffer_count < max_logs ? buffer_count : max_logs;
    *num_logs = count;
    
    if (count == 0) {
        return ESP_OK;
    }
    
    // Copy logs in chronological order (newest first)
    size_t idx = buffer_head;
    for (size_t i = 0; i < count; i++) {
        idx = (idx == 0) ? MAX_LOG_ENTRIES - 1 : idx - 1;
        memcpy(&logs[i], &log_buffer[idx], sizeof(attack_log_t));
    }
    
    return ESP_OK;
}

esp_err_t attack_logger_clear(void)
{
    ESP_LOGI(TAG, "Clearing all logs");
    
    buffer_head = 0;
    buffer_tail = 0;
    buffer_count = 0;
    
    // Clear flash storage
    flash_storage_clear_all();
    
    // Reset statistics (keep start time)
    stats.total_logged = 0;
    stats.last_log_time = 0;
    
    return ESP_OK;
}

esp_err_t attack_logger_get_stats(logger_stats_t *out_stats)
{
    if (out_stats == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    memcpy(out_stats, &stats, sizeof(logger_stats_t));
    return ESP_OK;
}

size_t attack_logger_count(void)
{
    return buffer_count;
}

static void log_to_console(const attack_log_t *log)
{
    struct tm *timeinfo = localtime(&log->timestamp);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    ESP_LOGI(TAG, "Attack logged: [%s] %s -> %s:%d | User: %s | Pass: %s | Hash: %s",
             time_str, log->source_ip, log->service, log->target_port,
             log->username, log->password, log->payload_hash);
}

// Format log entry as JSON for remote transmission
esp_err_t attack_logger_format_json(const attack_log_t *log, char *buffer, size_t buffer_size)
{
    if (log == NULL || buffer == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    struct tm *timeinfo = localtime(&log->timestamp);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", timeinfo);
    
    int written = snprintf(buffer, buffer_size,
        "{\"timestamp\":\"%s\","
        "\"source_ip\":\"%s\","
        "\"target_port\":%d,"
        "\"service\":\"%s\","
        "\"username\":\"%s\","
        "\"password\":\"%s\","
        "\"user_agent\":\"%s\","
        "\"payload_hash\":\"%s\","
        "\"metadata\":\"%s\"}",
        time_str, log->source_ip, log->target_port, log->service,
        log->username, log->password, log->user_agent,
        log->payload_hash, log->metadata);
    
    if (written < 0 || written >= buffer_size) {
        return ESP_ERR_INVALID_SIZE;
    }
    
    return ESP_OK;
}
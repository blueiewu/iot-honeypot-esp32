/*
 * IoT Honeypot - Main Entry Point
 * 
 * Author: Alex Chen
 * Created: 2023-10-15
 * Updated: 2024-01-20
 * Version: 1.2.0
 * 
 * Legal Disclaimer: For authorized security research only.
 */

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "honeypot.h"
#include "networking/wifi_manager.h"
#include "security/watchdog.h"
#include "utils/config.h"

static const char *TAG = "main";

// Function prototypes
static void initialize_nvs(void);
static void print_banner(void);
static void monitor_task(void *pvParameters);

void app_main(void)
{
    // Print startup banner
    print_banner();
    
    ESP_LOGI(TAG, "Starting IoT Honeypot v%s", HONEYPOT_VERSION);
    ESP_LOGI(TAG, "Build date: %s %s", __DATE__, __TIME__);
    
    // Initialize NVS
    initialize_nvs();
    
    // Initialize watchdog
    watchdog_init();
    ESP_LOGI(TAG, "Watchdog initialized");
    
    // Initialize WiFi
    if (wifi_init_sta() != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize WiFi");
        vTaskDelay(5000 / portTICK_PERIOD_MS);
        esp_restart();
    }
    
    // Wait for WiFi connection
    ESP_LOGI(TAG, "Waiting for WiFi connection...");
    vTaskDelay(3000 / portTICK_PERIOD_MS);
    
    // Create honeypot task
    if (honeypot_start() != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start honeypot");
        vTaskDelay(5000 / portTICK_PERIOD_MS);
        esp_restart();
    }
    
    // Create monitoring task
    xTaskCreate(monitor_task, "monitor_task", 4096, NULL, 2, NULL);
    
    ESP_LOGI(TAG, "Honeypot system initialized successfully");
}

static void initialize_nvs(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGI(TAG, "Erasing NVS partition");
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    ESP_LOGI(TAG, "NVS initialized");
}

static void print_banner(void)
{
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║                   IoT HONEYPOT ESP32                     ║\n");
    printf("║                     Version %s                        ║\n", HONEYPOT_VERSION);
    printf("║                                                          ║\n");
    printf("║  For authorized security research only.                  ║\n");
    printf("║  Comply with all applicable laws and regulations.        ║\n");
    printf("║                                                          ║\n");
    printf("║  Ports monitored: 21, 23, 80, 1883, 2323, 8080           ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

static void monitor_task(void *pvParameters)
{
    TickType_t xLastWakeTime = xTaskGetTickCount();
    
    while (1) {
        // Task runs every 30 seconds
        vTaskDelayUntil(&xLastWakeTime, pdMS_TO_TICKS(30000));
        
        // Log system status
        ESP_LOGI(TAG, "System monitor: Free heap: %d bytes", esp_get_free_heap_size());
        ESP_LOGI(TAG, "Minimum free heap: %d bytes", esp_get_minimum_free_heap_size());
        
        // Reset watchdog
        watchdog_feed();
    }
}
#ifndef HONEYPOT_H
#define HONEYPOT_H

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "utils/config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Honeypot configuration structure
 */
typedef struct {
    uint16_t ports[MAX_LISTENING_PORTS];  ///< Ports to listen on
    uint8_t port_count;                    ///< Number of ports
    uint32_t max_connections;              ///< Maximum concurrent connections
    uint32_t connection_timeout_ms;        ///< Connection timeout in milliseconds
    bool enable_logging;                   ///< Enable attack logging
    bool enable_remote_upload;             ///< Enable remote log upload
} honeypot_config_t;

/**
 * @brief Honeypot statistics
 */
typedef struct {
    uint32_t total_connections;            ///< Total connections received
    uint32_t attacks_logged;               ///< Total attacks logged
    uint32_t rate_limited;                 ///< Connections rate limited
    uint32_t http_attacks;                 ///< HTTP attacks detected
    uint32_t telnet_attacks;               ///< Telnet attacks detected
    uint32_t ftp_attacks;                  ///< FTP attacks detected
    uint32_t mqtt_attacks;                 ///< MQTT attacks detected
    time_t start_time;                     ///< Honeypot start time
} honeypot_stats_t;

/**
 * @brief Initialize honeypot with default configuration
 * 
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t honeypot_init(void);

/**
 * @brief Start honeypot main task
 * 
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t honeypot_start(void);

/**
 * @brief Stop honeypot and clean up resources
 * 
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t honeypot_stop(void);

/**
 * @brief Get current honeypot statistics
 * 
 * @param stats Pointer to store statistics
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t honeypot_get_stats(honeypot_stats_t *stats);

/**
 * @brief Reset honeypot statistics
 * 
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t honeypot_reset_stats(void);

/**
 * @brief Set honeypot configuration
 * 
 * @param config New configuration
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t honeypot_set_config(const honeypot_config_t *config);

/**
 * @brief Get current honeypot configuration
 * 
 * @param config Pointer to store configuration
 * @return esp_err_t ESP_OK on success, error code otherwise
 */
esp_err_t honeypot_get_config(honeypot_config_t *config);

#ifdef __cplusplus
}
#endif

#endif // HONEYPOT_H
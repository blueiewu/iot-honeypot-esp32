/*
 * HTTP Service Handler
 * 
 * Author: Maria Rodriguez
 * Created: 2023-11-05
 * Updated: 2024-01-15
 * 
 * Handles HTTP attacks and fake admin panel simulation
 */

#include "http_service.h"
#include "logging/attack_logger.h"
#include "utils/helpers.h"
#include "utils/md5_hash.h"
#include "esp_log.h"
#include <string.h>
#include <ctype.h>

static const char *TAG = "http_service";

// Fake admin panel HTML
static const char *FAKE_LOGIN_HTML = 
    "<!DOCTYPE html>\n"
    "<html lang='en'>\n"
    "<head>\n"
    "    <meta charset='UTF-8'>\n"
    "    <meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
    "    <title>Router Admin Panel</title>\n"
    "    <style>\n"
    "        body { font-family: Arial, sans-serif; margin: 40px; }\n"
    "        .container { max-width: 400px; margin: 0 auto; padding: 20px; border: 1px solid #ccc; }\n"
    "        .error { color: red; margin-top: 10px; }\n"
    "    </style>\n"
    "</head>\n"
    "<body>\n"
    "    <div class='container'>\n"
    "        <h2>Router Administration</h2>\n"
    "        <div class='error'>Access Denied: Invalid credentials</div>\n"
    "        <p>Please contact your network administrator.</p>\n"
    "    </div>\n"
    "</body>\n"
    "</html>";

static const char *HTTP_RESPONSE_TEMPLATE = 
    "HTTP/1.1 %d %s\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: %d\r\n"
    "Connection: close\r\n"
    "Server: Apache/2.4.41 (Ubuntu)\r\n"
    "\r\n"
    "%s";

void http_service_init(void)
{
    ESP_LOGI(TAG, "HTTP service initialized");
}

void http_service_handle_request(int sock_fd, const char *data, size_t len, 
                                 const char *client_ip, uint16_t port)
{
    // Parse HTTP request
    char method[16] = {0};
    char path[128] = {0};
    char user_agent[256] = {0};
    char authorization[256] = {0};
    
    if (!parse_http_request(data, method, path, user_agent, authorization)) {
        ESP_LOGW(TAG, "Invalid HTTP request from %s", client_ip);
        send_error_response(sock_fd, 400, "Bad Request");
        return;
    }
    
    ESP_LOGI(TAG, "HTTP %s %s from %s (User-Agent: %s)", 
             method, path, client_ip, user_agent);
    
    // Check for common attack paths
    if (strstr(path, "/shell") || strstr(path, "/cmd") || 
        strstr(path, "/exec") || strstr(path, "..")) {
        ESP_LOGW(TAG, "Potential path traversal attack from %s: %s", client_ip, path);
    }
    
    // Send fake response
    send_fake_response(sock_fd);
    
    // Log the attack
    log_http_attack(client_ip, port, method, path, user_agent, authorization, data, len);
}

static bool parse_http_request(const char *data, char *method, char *path, 
                               char *user_agent, char *authorization)
{
    if (data == NULL || strlen(data) < 10) {
        return false;
    }
    
    // Parse request line
    sscanf(data, "%15s %127s", method, path);
    
    // Parse headers
    const char *ptr = data;
    while (*ptr && (ptr = strstr(ptr, "\r\n")) != NULL) {
        ptr += 2; // Skip CRLF
        
        if (strncasecmp(ptr, "User-Agent:", 11) == 0) {
            ptr += 11;
            while (*ptr == ' ') ptr++;
            const char *end = strstr(ptr, "\r\n");
            if (end && (end - ptr) < 255) {
                strncpy(user_agent, ptr, end - ptr);
                user_agent[end - ptr] = '\0';
            }
        }
        else if (strncasecmp(ptr, "Authorization:", 14) == 0) {
            ptr += 14;
            while (*ptr == ' ') ptr++;
            const char *end = strstr(ptr, "\r\n");
            if (end && (end - ptr) < 255) {
                strncpy(authorization, ptr, end - ptr);
                authorization[end - ptr] = '\0';
            }
        }
        else if (*ptr == '\r' && *(ptr + 1) == '\n') {
            break; // End of headers
        }
    }
    
    return true;
}

static void send_fake_response(int sock_fd)
{
    char response[2048];
    snprintf(response, sizeof(response), HTTP_RESPONSE_TEMPLATE,
             403, "Forbidden", strlen(FAKE_LOGIN_HTML), FAKE_LOGIN_HTML);
    
    send(sock_fd, response, strlen(response), 0);
}

static void send_error_response(int sock_fd, int code, const char *message)
{
    char response[512];
    const char *body = "<html><body><h1>Error</h1><p>An error occurred.</p></body></html>";
    
    snprintf(response, sizeof(response), HTTP_RESPONSE_TEMPLATE,
             code, message, strlen(body), body);
    
    send(sock_fd, response, strlen(response), 0);
}

static void log_http_attack(const char *client_ip, uint16_t port, 
                            const char *method, const char *path,
                            const char *user_agent, const char *authorization,
                            const char *payload, size_t payload_len)
{
    attack_log_t log_entry = {0};
    
    log_entry.timestamp = time(NULL);
    strncpy(log_entry.source_ip, client_ip, sizeof(log_entry.source_ip) - 1);
    log_entry.target_port = port;
    strcpy(log_entry.service, "HTTP");
    strncpy(log_entry.username, "N/A", sizeof(log_entry.username) - 1);
    strncpy(log_entry.password, "N/A", sizeof(log_entry.password) - 1);
    strncpy(log_entry.user_agent, user_agent, sizeof(log_entry.user_agent) - 1);
    
    // Extract credentials from Authorization header if present
    if (authorization[0] != '\0') {
        strncpy(log_entry.password, authorization, sizeof(log_entry.password) - 1);
    }
    
    // Extract potential credentials from POST data
    if (strcmp(method, "POST") == 0) {
        extract_credentials_from_post(payload, log_entry.username, log_entry.password);
    }
    
    // Generate payload hash
    generate_md5_hash((const uint8_t *)payload, 
                     payload_len > 512 ? 512 : payload_len, 
                     log_entry.payload_hash);
    
    // Additional metadata
    snprintf(log_entry.metadata, sizeof(log_entry.metadata),
             "Method: %s, Path: %s", method, path);
    
    attack_logger_log(&log_entry);
}

static void extract_credentials_from_post(const char *data, char *username, char *password)
{
    // Look for common POST field names
    const char *patterns[] = {
        "username=", "user=", "login=", "uname=",
        "password=", "pass=", "pwd=", "passwd="
    };
    
    for (int i = 0; i < 4; i++) { // username patterns
        const char *found = strstr(data, patterns[i]);
        if (found) {
            const char *start = found + strlen(patterns[i]);
            const char *end = strchr(start, '&');
            if (!end) end = strchr(start, ' ');
            if (!end) end = start + strlen(start);
            
            size_t len = end - start;
            if (len < sizeof(username) - 1) {
                strncpy(username, start, len);
                username[len] = '\0';
                url_decode(username);
            }
        }
    }
    
    for (int i = 4; i < 8; i++) { // password patterns
        const char *found = strstr(data, patterns[i]);
        if (found) {
            const char *start = found + strlen(patterns[i]);
            const char *end = strchr(start, '&');
            if (!end) end = strchr(start, ' ');
            if (!end) end = start + strlen(start);
            
            size_t len = end - start;
            if (len < sizeof(password) - 1) {
                strncpy(password, start, len);
                password[len] = '\0';
                url_decode(password);
            }
        }
    }
}

static void url_decode(char *str)
{
    char *src = str;
    char *dst = str;
    
    while (*src) {
        if (*src == '%' && isxdigit(src[1]) && isxdigit(src[2])) {
            char hex[3] = {src[1], src[2], '\0'};
            *dst++ = (char)strtol(hex, NULL, 16);
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}
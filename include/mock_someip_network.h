#pragma once

/**
 * MockSomeipStack - vsomeip 网络模拟实现
 * 
 * 支持跨进程联调的 SOME/IP 模拟实现。
 * 使用 TCP socket 进行进程间通信，支持服务发现。
 * 
 * 使用方法：
 * - 在 CMakeLists.txt 中定义 USE_MOCK_SOMEIP
 * - 代码中通过 #ifdef 选择使用模拟或真实实现
 */

#include <memory>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <functional>
#include <mutex>
#include <atomic>
#include <thread>
#include <queue>
#include <condition_variable>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <utility>
#include <fstream>
#include <sstream>

// 网络相关头文件
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <netdb.h>
    #include <errno.h>
#endif

#include <nlohmann/json.hpp>

#include "sec_log_adapter.h"
#include "sec_log_context.h"

namespace mock_someip {

// 类型定义（对齐 vsomeip API）
using service_t = uint16_t;
using instance_t = uint16_t;
using method_t = uint16_t;
using session_t = uint16_t;
using client_id_t = uint16_t;

constexpr service_t ANY_SERVICE = 0xFFFF;
constexpr instance_t ANY_INSTANCE = 0xFFFF;
constexpr method_t ANY_METHOD = 0xFFFF;

// 消息类型
enum class message_type_e : uint8_t {
    REQUEST = 0x00,
    REQUEST_NO_RETURN = 0x01,
    NOTIFICATION = 0x02,
    RESPONSE = 0x80,
    ERROR = 0x81
};

// 返回码
enum class return_code_e : uint8_t {
    E_OK = 0x00,
    E_NOT_OK = 0x01,
    E_UNKNOWN_SERVICE = 0x02,
    E_UNKNOWN_METHOD = 0x03,
    E_NOT_READY = 0x04,
    E_NOT_REACHABLE = 0x05,
    E_TIMEOUT = 0x06,
    E_WRONG_PROTOCOL_VERSION = 0x07,
    E_WRONG_MESSAGE_TYPE = 0x08
};

// 前向声明
class Payload;
class Message;
class Request;
class Response;
class Runtime;
class Application;

// 网络消息头
struct NetworkMessageHeader {
    uint32_t magic;           // 0x534F4D45 ("SOME")
    uint16_t service_id;
    uint16_t instance_id;
    uint16_t method_id;
    uint16_t session_id;
    uint16_t client_id;
    uint8_t  message_type;
    uint8_t  return_code;
    uint32_t payload_length;
    
    static constexpr uint32_t MAGIC = 0x534F4D45; // "SOME" in ASCII
    
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data(sizeof(NetworkMessageHeader));
        size_t offset = 0;
        
        // magic (4 bytes)
        data[offset++] = (magic >> 24) & 0xFF;
        data[offset++] = (magic >> 16) & 0xFF;
        data[offset++] = (magic >> 8) & 0xFF;
        data[offset++] = magic & 0xFF;
        
        // service_id (2 bytes)
        data[offset++] = (service_id >> 8) & 0xFF;
        data[offset++] = service_id & 0xFF;
        
        // instance_id (2 bytes)
        data[offset++] = (instance_id >> 8) & 0xFF;
        data[offset++] = instance_id & 0xFF;
        
        // method_id (2 bytes)
        data[offset++] = (method_id >> 8) & 0xFF;
        data[offset++] = method_id & 0xFF;
        
        // session_id (2 bytes)
        data[offset++] = (session_id >> 8) & 0xFF;
        data[offset++] = session_id & 0xFF;
        
        // client_id (2 bytes)
        data[offset++] = (client_id >> 8) & 0xFF;
        data[offset++] = client_id & 0xFF;
        
        // message_type (1 byte)
        data[offset++] = message_type;
        
        // return_code (1 byte)
        data[offset++] = return_code;
        
        // payload_length (4 bytes)
        data[offset++] = (payload_length >> 24) & 0xFF;
        data[offset++] = (payload_length >> 16) & 0xFF;
        data[offset++] = (payload_length >> 8) & 0xFF;
        data[offset++] = payload_length & 0xFF;
        
        return data;
    }
    
    static bool deserialize(const uint8_t* data, size_t length, NetworkMessageHeader& header) {
        if (length < sizeof(NetworkMessageHeader)) {
            return false;
        }
        
        size_t offset = 0;
        
        // magic (4 bytes)
        header.magic = (data[offset] << 24) | (data[offset+1] << 16) | 
                       (data[offset+2] << 8) | data[offset+3];
        offset += 4;
        
        if (header.magic != MAGIC) {
            return false;
        }
        
        // service_id (2 bytes)
        header.service_id = (data[offset] << 8) | data[offset+1];
        offset += 2;
        
        // instance_id (2 bytes)
        header.instance_id = (data[offset] << 8) | data[offset+1];
        offset += 2;
        
        // method_id (2 bytes)
        header.method_id = (data[offset] << 8) | data[offset+1];
        offset += 2;
        
        // session_id (2 bytes)
        header.session_id = (data[offset] << 8) | data[offset+1];
        offset += 2;
        
        // client_id (2 bytes)
        header.client_id = (data[offset] << 8) | data[offset+1];
        offset += 2;
        
        // message_type (1 byte)
        header.message_type = data[offset++];
        
        // return_code (1 byte)
        header.return_code = data[offset++];
        
        // payload_length (4 bytes)
        header.payload_length = (data[offset] << 24) | (data[offset+1] << 16) | 
                                (data[offset+2] << 8) | data[offset+3];
        
        return true;
    }
};

// Payload 类
class Payload {
public:
    Payload() = default;
    Payload(const std::vector<uint8_t>& data) : data_(data) {}
    Payload(const uint8_t* data, size_t length) : data_(data, data + length) {}
    
    const uint8_t* get_data() const { return data_.data(); }
    size_t get_length() const { return data_.size(); }
    void set_data(const std::vector<uint8_t>& data) { data_ = data; }
    void set_data(const uint8_t* data, size_t length) { 
        data_.assign(data, data + length); 
    }
    
private:
    std::vector<uint8_t> data_;
};

// Message 基类
class Message {
public:
    virtual ~Message() = default;
    
    virtual service_t get_service() const = 0;
    virtual void set_service(service_t service) = 0;
    
    virtual instance_t get_instance() const = 0;
    virtual void set_instance(instance_t instance) = 0;
    
    virtual method_t get_method() const = 0;
    virtual void set_method(method_t method) = 0;
    
    virtual session_t get_session() const = 0;
    virtual void set_session(session_t session) = 0;
    
    virtual client_id_t get_client() const = 0;
    virtual void set_client(client_id_t client) = 0;
    
    virtual message_type_e get_message_type() const = 0;
    virtual void set_message_type(message_type_e type) = 0;
    
    virtual return_code_e get_return_code() const = 0;
    virtual void set_return_code(return_code_e code) = 0;
    
    virtual std::shared_ptr<Payload> get_payload() const = 0;
    virtual void set_payload(std::shared_ptr<Payload> payload) = 0;
    
    // 序列化为网络消息
    virtual std::vector<uint8_t> serialize_to_network() const {
        NetworkMessageHeader header;
        header.magic = NetworkMessageHeader::MAGIC;
        header.service_id = get_service();
        header.instance_id = get_instance();
        header.method_id = get_method();
        header.session_id = get_session();
        header.client_id = get_client();
        header.message_type = static_cast<uint8_t>(get_message_type());
        header.return_code = static_cast<uint8_t>(get_return_code());
        
        auto payload = get_payload();
        header.payload_length = payload ? payload->get_length() : 0;
        
        auto data = header.serialize();
        if (payload && payload->get_length() > 0) {
            data.insert(data.end(), payload->get_data(), 
                       payload->get_data() + payload->get_length());
        }
        
        return data;
    }
};

// Request 类
class Request : public Message {
public:
    Request() : service_(0), instance_(0), method_(0), session_(0), 
                client_(0), type_(message_type_e::REQUEST), code_(return_code_e::E_OK) {}
    
    service_t get_service() const override { return service_; }
    void set_service(service_t service) override { service_ = service; }
    
    instance_t get_instance() const override { return instance_; }
    void set_instance(instance_t instance) override { instance_ = instance; }
    
    method_t get_method() const override { return method_; }
    void set_method(method_t method) override { method_ = method; }
    
    session_t get_session() const override { return session_; }
    void set_session(session_t session) override { session_ = session; }
    
    client_id_t get_client() const override { return client_; }
    void set_client(client_id_t client) override { client_ = client; }
    
    message_type_e get_message_type() const override { return type_; }
    void set_message_type(message_type_e type) override { type_ = type; }
    
    return_code_e get_return_code() const override { return code_; }
    void set_return_code(return_code_e code) override { code_ = code; }
    
    std::shared_ptr<Payload> get_payload() const override { return payload_; }
    void set_payload(std::shared_ptr<Payload> payload) override { payload_ = payload; }
    
private:
    service_t service_;
    instance_t instance_;
    method_t method_;
    session_t session_;
    client_id_t client_;
    message_type_e type_;
    return_code_e code_;
    std::shared_ptr<Payload> payload_;
};

// Response 类
class Response : public Message {
public:
    Response() : service_(0), instance_(0), method_(0), session_(0), 
                 client_(0), type_(message_type_e::RESPONSE), code_(return_code_e::E_OK) {}
    
    // 从 Request 创建 Response
    static std::shared_ptr<Response> create(const std::shared_ptr<Request>& request) {
        auto response = std::make_shared<Response>();
        response->set_service(request->get_service());
        response->set_instance(request->get_instance());
        response->set_method(request->get_method());
        response->set_session(request->get_session());
        response->set_client(request->get_client());
        response->set_message_type(message_type_e::RESPONSE);
        return response;
    }
    
    service_t get_service() const override { return service_; }
    void set_service(service_t service) override { service_ = service; }
    
    instance_t get_instance() const override { return instance_; }
    void set_instance(instance_t instance) override { instance_ = instance; }
    
    method_t get_method() const override { return method_; }
    void set_method(method_t method) override { method_ = method; }
    
    session_t get_session() const override { return session_; }
    void set_session(session_t session) override { session_ = session; }
    
    client_id_t get_client() const override { return client_; }
    void set_client(client_id_t client) override { client_ = client; }
    
    message_type_e get_message_type() const override { return type_; }
    void set_message_type(message_type_e type) override { type_ = type; }
    
    return_code_e get_return_code() const override { return code_; }
    void set_return_code(return_code_e code) override { code_ = code; }
    
    std::shared_ptr<Payload> get_payload() const override { return payload_; }
    void set_payload(std::shared_ptr<Payload> payload) override { payload_ = payload; }
    
private:
    service_t service_;
    instance_t instance_;
    method_t method_;
    session_t session_;
    client_id_t client_;
    message_type_e type_;
    return_code_e code_;
    std::shared_ptr<Payload> payload_;
};

// 消息处理器类型
using message_handler_t = std::function<void(const std::shared_ptr<Message>&)>;
using availability_handler_t = std::function<void(service_t, instance_t, bool)>;

// 配置管理器
class ConfigManager {
public:
    static ConfigManager& get_instance() {
        static ConfigManager instance;
        return instance;
    }
    
    bool load_config(const std::string& config_path) {
        try {
            std::ifstream file(config_path);
            if (!file.is_open()) {
                cgw_sec::SecLogAdapter::facade().error("sec.network.config_load_failed",
                    "Failed to open network config file",
                    {cgw_sec::slog::f_str("config_path", config_path)});
                return false;
            }
            
            nlohmann::json config;
            file >> config;
            
            // 解析unicast地址
            if (config.contains("unicast")) {
                unicast_address_ = config["unicast"].get<std::string>();
            }
            
            // 解析服务配置
            if (config.contains("services")) {
                for (const auto& service_config : config["services"]) {
                    ServiceConfig svc_config;
                    svc_config.service_id = std::stoul(service_config["service"].get<std::string>(), nullptr, 16);
                    svc_config.instance_id = std::stoul(service_config["instance"].get<std::string>(), nullptr, 16);
                    
                    if (service_config.contains("reliable") && service_config["reliable"].contains("port")) {
                        svc_config.tcp_port = std::stoi(service_config["reliable"]["port"].get<std::string>());
                    }
                    
                    if (service_config.contains("unreliable")) {
                        svc_config.udp_port = std::stoi(service_config["unreliable"].get<std::string>());
                    }
                    
                    service_configs_[std::make_pair(svc_config.service_id, svc_config.instance_id)] = svc_config;
                }
            }
            
            // 解析应用配置
            if (config.contains("applications")) {
                for (const auto& app_config : config["applications"]) {
                    ApplicationConfig app_cfg;
                    app_cfg.name = app_config["name"].get<std::string>();
                    app_cfg.id = std::stoul(app_config["id"].get<std::string>(), nullptr, 16);
                    application_configs_[app_cfg.name] = app_cfg;
                }
            }
            
            config_loaded_ = true;
            return true;
            
        } catch (const std::exception& e) {
            cgw_sec::SecLogAdapter::facade().error("sec.network.config_parse_failed",
                "Failed to parse network config file",
                {cgw_sec::slog::f_str("config_path", config_path),
                 cgw_sec::slog::f_str("error_message", e.what())});
            return false;
        }
    }
    
    std::string get_unicast_address() const { return unicast_address_; }
    
    bool is_config_loaded() const { return config_loaded_; }
    
public:
    struct ServiceConfig {
        service_t service_id;
        instance_t instance_id;
        int tcp_port = 0;
        int udp_port = 0;
    };
    
    struct ApplicationConfig {
        std::string name;
        client_id_t id;
    };
    
    bool get_service_config(service_t service, instance_t instance, ServiceConfig& config) const {
        auto key = std::make_pair(service, instance);
        auto it = service_configs_.find(key);
        if (it != service_configs_.end()) {
            config = it->second;
            return true;
        }
        return false;
    }
    
    bool get_application_config(const std::string& name, ApplicationConfig& config) const {
        auto it = application_configs_.find(name);
        if (it != application_configs_.end()) {
            config = it->second;
            return true;
        }
        return false;
    }
    
private:
    ConfigManager() = default;
    
    std::string unicast_address_ = "127.0.0.1";
    std::map<std::pair<service_t, instance_t>, ServiceConfig> service_configs_;
    std::map<std::string, ApplicationConfig> application_configs_;
    bool config_loaded_ = false;
};

// 网络连接管理器
class NetworkManager {
public:
    static NetworkManager& get_instance() {
        static NetworkManager instance;
        return instance;
    }
    
    bool initialize() {
#ifdef _WIN32
        WSADATA wsaData;
        return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
#else
        return true;
#endif
    }
    
    void cleanup() {
#ifdef _WIN32
        WSACleanup();
#endif
    }
    
    // 创建TCP服务器socket
    int create_tcp_server(const std::string& address, int port) {
        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) {
            cgw_sec::SecLogAdapter::facade().error("sec.network.socket_create_failed",
                "Failed to create socket",
                {cgw_sec::slog::f_str("error_message", strerror(errno)),
                 cgw_sec::slog::f_int("errno", errno)});
            return -1;
        }
        
        int opt = 1;
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) < 0) {
            cgw_sec::SecLogAdapter::facade().error("sec.network.socket_option_failed",
                "Failed to set socket options",
                {cgw_sec::slog::f_str("error_message", strerror(errno)),
                 cgw_sec::slog::f_int("errno", errno)});
            close_socket(server_fd);
            return -1;
        }
        
        struct sockaddr_in address_struct;
        address_struct.sin_family = AF_INET;
        address_struct.sin_addr.s_addr = inet_addr(address.c_str());
        address_struct.sin_port = htons(port);
        
        if (bind(server_fd, (struct sockaddr*)&address_struct, sizeof(address_struct)) < 0) {
            cgw_sec::SecLogAdapter::facade().error("sec.network.bind_failed",
                "Failed to bind socket",
                {cgw_sec::slog::f_str("error_message", strerror(errno)),
                 cgw_sec::slog::f_int("errno", errno),
                 cgw_sec::slog::f_int("someip_port", port)});
            close_socket(server_fd);
            return -1;
        }
        
        if (listen(server_fd, 3) < 0) {
            cgw_sec::SecLogAdapter::facade().error("sec.network.listen_failed",
                "Failed to listen on socket",
                {cgw_sec::slog::f_str("error_message", strerror(errno)),
                 cgw_sec::slog::f_int("errno", errno)});
            close_socket(server_fd);
            return -1;
        }
        
        return server_fd;
    }
    
    // 创建TCP客户端socket
    int create_tcp_client(const std::string& address, int port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            cgw_sec::SecLogAdapter::facade().error("sec.network.socket_create_failed",
                "Failed to create socket",
                {cgw_sec::slog::f_str("error_message", strerror(errno)),
                 cgw_sec::slog::f_int("errno", errno)});
            return -1;
        }
        
        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        
        if (inet_pton(AF_INET, address.c_str(), &serv_addr.sin_addr) <= 0) {
            cgw_sec::SecLogAdapter::facade().error("sec.network.invalid_address",
                "Invalid network address",
                {cgw_sec::slog::f_str("address", address)});
            close_socket(sock);
            return -1;
        }
        
        if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
            cgw_sec::SecLogAdapter::facade().error("sec.network.connect_failed",
                "Connection failed",
                {cgw_sec::slog::f_str("error_message", strerror(errno)),
                 cgw_sec::slog::f_int("errno", errno)});
            close_socket(sock);
            return -1;
        }
        
        return sock;
    }
    
    // 发送数据
    bool send_data(int sock, const std::vector<uint8_t>& data) {
        size_t total_sent = 0;
        while (total_sent < data.size()) {
            ssize_t sent = send(sock, data.data() + total_sent, data.size() - total_sent, 0);
            if (sent < 0) {
                cgw_sec::SecLogAdapter::facade().error("sec.network.send_failed",
                    "Failed to send data",
                    {cgw_sec::slog::f_str("error_message", strerror(errno)),
                     cgw_sec::slog::f_int("errno", errno)});
                return false;
            }
            total_sent += sent;
        }
        return true;
    }
    
    // 接收数据
    bool receive_data(int sock, std::vector<uint8_t>& data, size_t length) {
        data.resize(length);
        size_t total_received = 0;
        while (total_received < length) {
            ssize_t received = recv(sock, data.data() + total_received, length - total_received, 0);
            if (received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // 非阻塞socket没有数据，继续等待
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                }
                cgw_sec::SecLogAdapter::facade().error("sec.network.receive_failed",
                    "Failed to receive data",
                    {cgw_sec::slog::f_str("error_message", strerror(errno)),
                     cgw_sec::slog::f_int("errno", errno)});
                return false;
            } else if (received == 0) {
                // 连接关闭
                return false;
            }
            total_received += received;
        }
        return true;
    }
    
    // 接收完整消息
    bool receive_message(int sock, NetworkMessageHeader& header, std::vector<uint8_t>& payload) {
        // 接收头部
        std::vector<uint8_t> header_data;
        if (!receive_data(sock, header_data, sizeof(NetworkMessageHeader))) {
            return false;
        }
        
        if (!NetworkMessageHeader::deserialize(header_data.data(), header_data.size(), header)) {
            cgw_sec::SecLogAdapter::facade().error("sec.network.deserialize_failed",
                "Failed to deserialize message header");
            return false;
        }
        
        // 接收payload
        if (header.payload_length > 0) {
            if (!receive_data(sock, payload, header.payload_length)) {
                return false;
            }
        }
        
        return true;
    }
    
    void close_socket(int sock) {
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
    }
    
private:
    NetworkManager() = default;
};

// 服务注册表（支持网络同步）
class ServiceRegistry {
public:
    static ServiceRegistry& get_instance() {
        static ServiceRegistry instance;
        return instance;
    }
    
    void register_service(service_t service, instance_t instance) {
        std::vector<availability_handler_t> handlers;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            services_[service].insert(instance);
            
            // 收集需要通知的处理器
            auto key = std::make_pair(service, instance);
            auto it = availability_handlers_.find(key);
            if (it != availability_handlers_.end()) {
                for (auto& entry : it->second) {
                    handlers.push_back(entry.handler);
                }
            }
        }
        
        // 在锁外通知所有等待的客户端
        for (auto& handler : handlers) {
            handler(service, instance, true);
        }
    }
    
    void unregister_service(service_t service, instance_t instance) {
        std::vector<availability_handler_t> handlers;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (services_.count(service)) {
                services_[service].erase(instance);
                if (services_[service].empty()) {
                    services_.erase(service);
                }
            }
            
            // 收集需要通知的处理器
            auto key = std::make_pair(service, instance);
            auto it = availability_handlers_.find(key);
            if (it != availability_handlers_.end()) {
                for (auto& entry : it->second) {
                    handlers.push_back(entry.handler);
                }
            }
        }
        
        // 在锁外通知所有等待的客户端
        for (auto& handler : handlers) {
            handler(service, instance, false);
        }
    }
    
    bool is_service_available(service_t service, instance_t instance) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return is_service_available_locked(service, instance);
    }
    
    void register_availability_handler(service_t service, instance_t instance,
                                       const void* owner,
                                       availability_handler_t handler) {
        bool should_notify = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto key = std::make_pair(service, instance);
            availability_handlers_[key].push_back({owner, handler});
            
            should_notify = is_service_available_locked(service, instance);
        }
        
        if (should_notify) {
            handler(service, instance, true);
        }
    }
    
    void remove_handlers(const void* owner) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = availability_handlers_.begin(); it != availability_handlers_.end();) {
            auto& vec = it->second;
            vec.erase(std::remove_if(vec.begin(), vec.end(),
                                     [owner](const HandlerEntry& e) { return e.owner == owner; }),
                      vec.end());
            if (vec.empty()) {
                it = availability_handlers_.erase(it);
            } else {
                ++it;
            }
        }
    }
    
    void register_offerer(service_t service, instance_t instance, Application* app) {
        std::lock_guard<std::mutex> lock(mutex_);
        offerers_[std::make_pair(service, instance)] = app;
    }
    
    void unregister_offerer(service_t service, instance_t instance, Application* app) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto key = std::make_pair(service, instance);
        auto it = offerers_.find(key);
        if (it != offerers_.end() && it->second == app) {
            offerers_.erase(it);
        }
    }
    
    Application* find_offerer(service_t service, instance_t instance) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = offerers_.find(std::make_pair(service, instance));
        return it != offerers_.end() ? it->second : nullptr;
    }
    
    void register_application(client_id_t id, Application* app) {
        std::lock_guard<std::mutex> lock(mutex_);
        applications_[id] = app;
    }
    
    void unregister_application(client_id_t id) {
        std::lock_guard<std::mutex> lock(mutex_);
        applications_.erase(id);
    }
    
    Application* find_application(client_id_t id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = applications_.find(id);
        return it != applications_.end() ? it->second : nullptr;
    }
    
private:
    ServiceRegistry() = default;
    
    bool is_service_available_locked(service_t service, instance_t instance) const {
        auto it = services_.find(service);
        if (it != services_.end()) {
            return it->second.count(instance) > 0;
        }
        return false;
    }
    
    struct HandlerEntry {
        const void* owner;
        availability_handler_t handler;
    };
    
    mutable std::mutex mutex_;
    std::map<service_t, std::set<instance_t>> services_;
    std::map<std::pair<service_t, instance_t>, std::vector<HandlerEntry>> availability_handlers_;
    std::map<std::pair<service_t, instance_t>, Application*> offerers_;
    std::map<client_id_t, Application*> applications_;
};

// Runtime 类（单例）
class Runtime {
public:
    static std::shared_ptr<Runtime> get() {
        static std::shared_ptr<Runtime> instance = std::shared_ptr<Runtime>(new Runtime());
        return instance;
    }
    
    std::shared_ptr<Request> create_request() {
        return std::make_shared<Request>();
    }
    
    std::shared_ptr<Message> create_response(const std::shared_ptr<Message>& request) {
        auto response = std::make_shared<Response>();
        response->set_service(request->get_service());
        response->set_instance(request->get_instance());
        response->set_method(request->get_method());
        response->set_session(request->get_session());
        response->set_client(request->get_client());
        response->set_message_type(message_type_e::RESPONSE);
        return response;
    }
    
    std::shared_ptr<Payload> create_payload() {
        return std::make_shared<Payload>();
    }
    
    std::shared_ptr<Application> create_application(const std::string& name);
    
private:
    Runtime() = default;
};

// Application 类（支持网络通信）
class Application : public std::enable_shared_from_this<Application> {
public:
    Application(const std::string& name) : name_(name), running_(false) {
        static std::atomic<client_id_t> next_id{1};
        client_id_ = next_id.fetch_add(1);
        ServiceRegistry::get_instance().register_application(client_id_, this);
        
        // 初始化网络管理器
        NetworkManager::get_instance().initialize();
    }
    
    ~Application() {
        stop();
        ServiceRegistry::get_instance().unregister_application(client_id_);
        NetworkManager::get_instance().cleanup();
    }
    
    void init() {
        // 加载配置
        auto& config_mgr = ConfigManager::get_instance();
        if (!config_mgr.is_config_loaded()) {
            // 尝试加载默认配置文件
            config_mgr.load_config("config/vsomeip.json");
        }
        
        // 获取应用配置
        ConfigManager::ApplicationConfig app_config;
        if (config_mgr.get_application_config(name_, app_config)) {
            client_id_ = app_config.id;
        }
    }
    
    bool start() {
        if (running_) return true;
        running_ = true;
        
        // 启动事件循环线程
        event_loop_thread_ = std::thread([this]() {
            while (running_) {
                std::shared_ptr<Message> msg;
                {
                    std::unique_lock<std::mutex> lock(queue_mutex_);
                    cv_.wait_for(lock, std::chrono::milliseconds(100), 
                                [this]() { return !message_queue_.empty() || !running_; });
                    
                    if (!running_) break;
                    if (message_queue_.empty()) continue;
                    
                    msg = message_queue_.front();
                    message_queue_.pop();
                }
                
                // 处理消息
                process_message(msg);
            }
        });
        
        // 启动网络服务器线程（如果配置了端口）
        start_network_server();
        
        return true;
    }
    
    void stop() {
        running_ = false;
        stop_requested_ = true;
        cv_.notify_all();
        
        // 停止网络服务器
        stop_network_server();
        
        if (event_loop_thread_.joinable()) {
            event_loop_thread_.join();
        }
        
        // 从全局注册表移除本 Application 的所有痕迹
        auto& registry = ServiceRegistry::get_instance();
        registry.remove_handlers(this);
        
        std::map<service_t, std::set<instance_t>> offered_copy;
        {
            std::lock_guard<std::mutex> lock(services_mutex_);
            offered_copy.swap(offered_services_);
            requested_services_.clear();
        }
        for (auto& svc : offered_copy) {
            for (auto inst : svc.second) {
                registry.unregister_offerer(svc.first, inst, this);
                registry.unregister_service(svc.first, inst);
            }
        }
    }
    
    void offer_service(service_t service, instance_t instance) {
        {
            std::lock_guard<std::mutex> lock(services_mutex_);
            offered_services_[service].insert(instance);
        }
        
        // 使用全局服务注册表
        ServiceRegistry::get_instance().register_offerer(service, instance, this);
        ServiceRegistry::get_instance().register_service(service, instance);
        
        // 如果配置了网络端口，启动网络监听
        start_service_network(service, instance);
    }
    
    void stop_offer_service(service_t service, instance_t instance) {
        {
            std::lock_guard<std::mutex> lock(services_mutex_);
            if (offered_services_.count(service)) {
                offered_services_[service].erase(instance);
                if (offered_services_[service].empty()) {
                    offered_services_.erase(service);
                }
            }
        }
        
        // 使用全局服务注册表
        ServiceRegistry::get_instance().unregister_offerer(service, instance, this);
        ServiceRegistry::get_instance().unregister_service(service, instance);
        
        // 停止网络监听
        stop_service_network(service, instance);
    }
    
    void request_service(service_t service, instance_t instance) {
        {
            std::lock_guard<std::mutex> lock(services_mutex_);
            requested_services_[service].insert(instance);
        }
        
        // 注册到全局服务注册表
        ServiceRegistry::get_instance().register_availability_handler(
            service, instance, this,
            [this](service_t s, instance_t i, bool available) {
                notify_availability(s, i, available);
            });
        
        // 尝试连接到远程服务
        connect_to_remote_service(service, instance);
    }
    
    void offer_method(service_t service, instance_t instance, method_t method) {
        std::lock_guard<std::mutex> lock(methods_mutex_);
        offered_methods_[{service, instance}].insert(method);
    }
    
    void register_message_handler(service_t service, instance_t instance, 
                                  method_t method, message_handler_t handler) {
        std::lock_guard<std::mutex> lock(handlers_mutex_);
        message_handlers_[{service, instance, method}] = handler;
    }
    
    void register_availability_handler(service_t service, instance_t instance,
                                       availability_handler_t handler) {
        {
            std::lock_guard<std::mutex> lock(handlers_mutex_);
            availability_handlers_[{service, instance}].push_back(handler);
        }
        
        // 如果服务已经可用，立即通知
        if (ServiceRegistry::get_instance().is_service_available(service, instance)) {
            handler(service, instance, true);
        }
    }
    
    void send(const std::shared_ptr<Message>& message) {
        try {
        auto& registry = ServiceRegistry::get_instance();
        auto type = message->get_message_type();
        
        // 检查是否正在处理网络请求
        if (current_network_client_fd_ >= 0 && 
            (type == message_type_e::RESPONSE || type == message_type_e::ERROR)) {
            // 直接发送到当前网络客户端
            auto data = message->serialize_to_network();
            NetworkManager::get_instance().send_data(current_network_client_fd_, data);
            return;
        }
        
        if (type == message_type_e::REQUEST ||
            type == message_type_e::REQUEST_NO_RETURN) {
            // 请求：标记发送者 client_id 以便响应回送
            message->set_client(client_id_);
            
            // 首先尝试本地路由
            Application* target = registry.find_offerer(message->get_service(), message->get_instance());
            if (target) {
                target->enqueue(message);
                return;
            }
            
            // 尝试网络路由
            if (send_via_network(message)) {
                return;
            }
            
            // 未找到服务端：回退到本地队列
            enqueue(message);
        } else {
            // 响应/通知：按请求方 client_id 回送到发起请求的应用
            Application* target = registry.find_application(message->get_client());
            if (target) {
                target->enqueue(message);
                return;
            }
            
            // 尝试网络路由
            if (send_via_network(message)) {
                return;
            }
            
            // 检查是否是网络客户端
            {
                std::lock_guard<std::mutex> lock(network_mutex_);
                auto it = network_client_sockets_.find(message->get_client());
                if (it != network_client_sockets_.end()) {
                    // 发送到网络客户端
                    auto data = message->serialize_to_network();
                    NetworkManager::get_instance().send_data(it->second, data);
                    return;
                }
            }
            
            enqueue(message);
        }
        } catch (const std::exception& e) {
            cgw_sec::SecLogAdapter::facade().error("sec.network.send_exception",
                "Exception in send()",
                {cgw_sec::slog::f_str("error_message", e.what())});
        } catch (...) {
            cgw_sec::SecLogAdapter::facade().error("sec.network.send_exception",
                "Unknown exception in send()");
        }
    }
    
    // 通过网络发送响应
    void send_response_via_network(const std::shared_ptr<Message>& response, int client_fd) {
        auto data = response->serialize_to_network();
        NetworkManager::get_instance().send_data(client_fd, data);
    }
    
    void enqueue(const std::shared_ptr<Message>& message) {
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            message_queue_.push(message);
        }
        cv_.notify_one();
    }
    
    client_id_t get_client_id() const { return client_id_; }
    
    const std::string& get_name() const { return name_; }
    
    // 同步 RPC 调用（用于客户端网络模式）
    // 如果没有网络连接，返回空（由调用者回退到进程内通信）
    std::vector<uint8_t> send_rpc(service_t service, instance_t instance, method_t method,
                                  const std::vector<uint8_t>& payload) {
        std::lock_guard<std::mutex> lock(network_mutex_);
        auto key = std::make_pair(service, instance);
        auto it = client_sockets_.find(key);
        if (it == client_sockets_.end()) {
            // 没有网络连接，返回空让调用者回退
            return {};
        }
        
        int sock = it->second;
        
        // 构造请求消息
        NetworkMessageHeader header;
        header.magic = NetworkMessageHeader::MAGIC;
        header.service_id = service;
        header.instance_id = instance;
        header.method_id = method;
        header.session_id = 1;
        header.client_id = client_id_;
        header.message_type = static_cast<uint8_t>(message_type_e::REQUEST);
        header.return_code = static_cast<uint8_t>(return_code_e::E_OK);
        header.payload_length = payload.size();
        
        auto headerData = header.serialize();
        if (!NetworkManager::get_instance().send_data(sock, headerData)) {
            return {};
        }
        if (!NetworkManager::get_instance().send_data(sock, payload)) {
            return {};
        }
        
        // 接收响应
        NetworkMessageHeader respHeader;
        std::vector<uint8_t> respPayload;
        if (!NetworkManager::get_instance().receive_message(sock, respHeader, respPayload)) {
            return {};
        }
        
        return respPayload;
    }
    
private:
    std::string name_;
    std::atomic<bool> running_;
    std::thread event_loop_thread_;
    client_id_t client_id_;
    
    // 服务管理
    std::mutex services_mutex_;
    std::map<service_t, std::set<instance_t>> offered_services_;
    std::map<service_t, std::set<instance_t>> requested_services_;
    
    // 方法管理
    std::mutex methods_mutex_;
    std::map<std::pair<service_t, instance_t>, std::set<method_t>> offered_methods_;
    
    // 处理器
    std::mutex handlers_mutex_;
    std::map<std::tuple<service_t, instance_t, method_t>, message_handler_t> message_handlers_;
    std::map<std::pair<service_t, instance_t>, std::vector<availability_handler_t>> availability_handlers_;
    
    // 消息队列
    std::mutex queue_mutex_;
    std::condition_variable cv_;
    std::queue<std::shared_ptr<Message>> message_queue_;
    
    // 网络相关
    std::mutex network_mutex_;
    std::map<std::pair<service_t, instance_t>, int> service_sockets_; // 服务端socket
    std::map<std::pair<service_t, instance_t>, int> client_sockets_;  // 客户端socket
    // 客户端处理线程，按唯一的连接序号索引。
    // 不能用 fd 做 key：fd 会被内核复用，若某个已结束但尚未 join 的线程仍留在 map 中，
    // 对其做 client_threads_[fd] = std::move(...) 会对一个 joinable 线程执行移动赋值，
    // 从而触发 std::terminate（即 "libc++abi: terminating" 崩溃）。
    std::map<uint64_t, std::thread> client_threads_; // 客户端处理线程（按连接序号索引）
    std::vector<uint64_t> finished_client_conn_ids_; // 已结束、待回收的客户端连接序号
    uint64_t next_client_conn_id_ = 0; // 客户端连接序号分配器
    std::map<client_id_t, int> network_client_sockets_; // 网络客户端socket映射
    std::thread accept_thread_;
    int server_socket_ = -1;
    std::atomic<bool> stop_requested_{false};
    
    // 线程局部变量，用于跟踪当前正在处理的网络客户端socket
    static thread_local int current_network_client_fd_;
    
    bool is_service_offered(service_t service, instance_t instance) const {
        auto it = offered_services_.find(service);
        if (it != offered_services_.end()) {
            return it->second.count(instance) > 0;
        }
        return false;
    }
    
    void notify_availability(service_t service, instance_t instance, bool available) {
        std::vector<availability_handler_t> handlers;
        {
            std::lock_guard<std::mutex> lock(handlers_mutex_);
            auto key = std::make_pair(service, instance);
            auto it = availability_handlers_.find(key);
            if (it != availability_handlers_.end()) {
                handlers = it->second;
            }
        }
        
        for (auto& handler : handlers) {
            handler(service, instance, available);
        }
    }
    
    void process_message(const std::shared_ptr<Message>& message) {
        message_handler_t handler;
        {
            std::lock_guard<std::mutex> lock(handlers_mutex_);
            auto key = std::make_tuple(message->get_service(),
                                       message->get_instance(),
                                       message->get_method());
            auto it = message_handlers_.find(key);
            if (it == message_handlers_.end()) {
                auto any_key = std::make_tuple(message->get_service(),
                                               message->get_instance(),
                                               ANY_METHOD);
                it = message_handlers_.find(any_key);
            }
            if (it != message_handlers_.end()) {
                handler = it->second;
            }
        }
        
        if (handler) {
            handler(message);
        }
    }
    
    using response_sender_t = std::function<void(const std::shared_ptr<Message>&)>;
    
    void process_message_with_response(const std::shared_ptr<Message>& message, 
                                       response_sender_t response_sender) {
        message_handler_t handler;
        {
            std::lock_guard<std::mutex> lock(handlers_mutex_);
            auto key = std::make_tuple(message->get_service(),
                                       message->get_instance(),
                                       message->get_method());
            auto it = message_handlers_.find(key);
            if (it == message_handlers_.end()) {
                auto any_key = std::make_tuple(message->get_service(),
                                               message->get_instance(),
                                               ANY_METHOD);
                it = message_handlers_.find(any_key);
            }
            if (it != message_handlers_.end()) {
                handler = it->second;
            }
        }
        
        if (handler) {
            // 创建一个包装器，将响应发送到网络
            auto wrapped_handler = [handler, response_sender](const std::shared_ptr<Message>& msg) {
                // 创建一个响应对象
                auto response = std::make_shared<Response>();
                response->set_service(msg->get_service());
                response->set_instance(msg->get_instance());
                response->set_method(msg->get_method());
                response->set_session(msg->get_session());
                response->set_client(msg->get_client());
                response->set_message_type(message_type_e::RESPONSE);
                response->set_return_code(return_code_e::E_OK);
                
                // 调用原始处理器
                handler(msg);
                
                // 注意：在当前的架构中，处理器会创建响应并调用 application_->send(response)
                // 但这里我们需要将响应发送到网络客户端
                // 暂时我们假设处理器会通过 send 函数发送响应
                // 但实际上，我们需要修改处理器的逻辑
            };
            
            wrapped_handler(message);
        }
    }
    
    void handle_network_request(const std::shared_ptr<Message>& request, int client_fd) {
        message_handler_t handler;
        {
            std::lock_guard<std::mutex> lock(handlers_mutex_);
            auto key = std::make_tuple(request->get_service(),
                                       request->get_instance(),
                                       request->get_method());
            auto it = message_handlers_.find(key);
            if (it == message_handlers_.end()) {
                auto any_key = std::make_tuple(request->get_service(),
                                               request->get_instance(),
                                               ANY_METHOD);
                it = message_handlers_.find(any_key);
            }
            if (it != message_handlers_.end()) {
                handler = it->second;
            }
        }
        
        if (handler) {
            // 创建响应
            auto response = std::make_shared<Response>();
            response->set_service(request->get_service());
            response->set_instance(request->get_instance());
            response->set_method(request->get_method());
            response->set_session(request->get_session());
            response->set_client(request->get_client());
            response->set_message_type(message_type_e::RESPONSE);
            response->set_return_code(return_code_e::E_OK);
            
            // 调用处理器
            handler(request);
            
            // 注意：处理器会调用 application_->send(response)
            // 但 send() 函数会尝试通过网络发送响应
            // 由于我们在处理网络请求，我们需要确保响应被发送回客户端
        }
    }
    
    void start_network_server() {
        auto& config_mgr = ConfigManager::get_instance();
        if (!config_mgr.is_config_loaded()) {
            return;
        }
        
        // 检查是否有服务需要监听
        std::lock_guard<std::mutex> lock(services_mutex_);
        for (const auto& service : offered_services_) {
            for (const auto& instance : service.second) {
                start_service_network(service.first, instance);
            }
        }
    }
    
    void stop_network_server() {
        // 先请求停止，让 accept 线程尽快退出循环（不再调用 reap / 不再 accept 新连接）
        stop_requested_ = true;

        std::vector<std::thread> threads_to_join;
        {
            std::lock_guard<std::mutex> lock(network_mutex_);

            // 关闭所有服务端socket
            for (auto& pair : service_sockets_) {
                NetworkManager::get_instance().close_socket(pair.second);
            }
            service_sockets_.clear();

            // 关闭所有客户端socket
            for (auto& pair : client_sockets_) {
                NetworkManager::get_instance().close_socket(pair.second);
            }
            client_sockets_.clear();

            // 关闭服务器socket
            if (server_socket_ >= 0) {
                NetworkManager::get_instance().close_socket(server_socket_);
                server_socket_ = -1;
            }

            // 把客户端线程移出 map，稍后在锁外 join。
            // 不能持锁 join：客户端线程收尾时也要获取 network_mutex_，持锁 join 会死锁。
            for (auto& pair : client_threads_) {
                if (pair.second.joinable()) {
                    threads_to_join.push_back(std::move(pair.second));
                }
            }
            client_threads_.clear();
            finished_client_conn_ids_.clear();
        }

        // 在锁外等待所有客户端线程结束
        for (auto& t : threads_to_join) {
            if (t.joinable()) {
                t.join();
            }
        }

        // 在锁外等待 accept 线程结束（accept 线程内部也会获取 network_mutex_）
        if (accept_thread_.joinable()) {
            accept_thread_.join();
        }
    }
    
    void start_service_network(service_t service, instance_t instance) {
        auto& config_mgr = ConfigManager::get_instance();
        ConfigManager::ServiceConfig config;
        if (!config_mgr.get_service_config(service, instance, config)) {
            return;
        }
        
        if (config.tcp_port <= 0) {
            return;
        }
        
        std::lock_guard<std::mutex> lock(network_mutex_);
        auto key = std::make_pair(service, instance);
        if (service_sockets_.find(key) != service_sockets_.end()) {
            return; // 已经启动
        }
        
        int server_fd = NetworkManager::get_instance().create_tcp_server(
            config_mgr.get_unicast_address(), config.tcp_port);
        
        if (server_fd < 0) {
            cgw_sec::SecLogAdapter::facade().error("sec.network.server_start_failed",
                "Failed to start network server",
                {cgw_sec::slog::f_str("someip_service_id", cgw_sec::hex_id(service)),
                 cgw_sec::slog::f_str("someip_instance_id", cgw_sec::hex_id(instance))});
            return;
        }
        
        service_sockets_[key] = server_fd;
        
        // 启动接受连接的线程
        accept_thread_ = std::thread([this, server_fd, service, instance]() {
            
            // 设置socket为非阻塞模式，以便能够检查running_标志
            int flags = fcntl(server_fd, F_GETFL, 0);
            fcntl(server_fd, F_SETFL, flags | O_NONBLOCK);
            
            // 等待running_被设置为true
            while (!running_ && !stop_requested_) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            
            
            while (running_ && !stop_requested_) {
                // 回收上一轮已结束的客户端线程
                reap_finished_client_threads();

                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                
                int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
                
                if (client_fd < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        // 没有连接等待，继续循环
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        continue;
                    }
                    if (running_) {
                        cgw_sec::SecLogAdapter::facade().error("sec.network.accept_failed",
                            "Failed to accept connection",
                            {cgw_sec::slog::f_str("error_message", strerror(errno)),
                             cgw_sec::slog::f_int("errno", errno)});
                    }
                    continue;
                }
                
                {
                    char client_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
                    int client_port = ntohs(client_addr.sin_port);
                    cgw_sec::SecLogAdapter::facade().info("sec.network.client_connected",
                        "Client connected",
                        {cgw_sec::slog::f_int("client_fd", client_fd),
                         cgw_sec::slog::f_str("client_addr", std::string(client_ip) + ":" + std::to_string(client_port)),
                         cgw_sec::slog::f_str("someip_service_id", cgw_sec::hex_id(service)),
                         cgw_sec::slog::f_str("someip_instance_id", cgw_sec::hex_id(instance))});
                }
                
                // 为本次连接分配唯一序号（用于线程索引，避免 fd 复用导致的键冲突）
                uint64_t conn_id;
                {
                    std::lock_guard<std::mutex> lock(network_mutex_);
                    conn_id = next_client_conn_id_++;
                }

                // 启动客户端处理线程
                std::thread client_thread([this, client_fd, service, instance, conn_id]() {
                    try {
                        handle_client_connection(client_fd, service, instance);
                    } catch (const std::exception& e) {
                        cgw_sec::SecLogAdapter::facade().error("sec.network.client_handler_exception",
                            "Client handler exception",
                            {cgw_sec::slog::f_int("client_fd", client_fd),
                             cgw_sec::slog::f_str("error_message", e.what())});
                    } catch (...) {
                        cgw_sec::SecLogAdapter::facade().error("sec.network.client_handler_exception",
                            "Unknown exception in client handler",
                            {cgw_sec::slog::f_int("client_fd", client_fd)});
                    }
                    // 标记本线程已结束，交由 accept 线程回收（不能在此处 join 自己）
                    std::lock_guard<std::mutex> lock(network_mutex_);
                    finished_client_conn_ids_.push_back(conn_id);
                });
                
                {
                    std::lock_guard<std::mutex> lock(network_mutex_);
                    // conn_id 唯一且递增，map 中必然不存在该 key，
                    // 因此这里是对一个默认构造（非 joinable）的线程做移动赋值，安全。
                    client_threads_[conn_id] = std::move(client_thread);
                }
            }
        });
        
        cgw_sec::SecLogAdapter::facade().info("sec.network.server_started",
            "Network server started",
            {cgw_sec::slog::f_str("someip_service_id", cgw_sec::hex_id(service)),
             cgw_sec::slog::f_str("someip_instance_id", cgw_sec::hex_id(instance)),
             cgw_sec::slog::f_int("someip_port", config.tcp_port)});
    }
    
    void stop_service_network(service_t service, instance_t instance) {
        std::lock_guard<std::mutex> lock(network_mutex_);
        auto key = std::make_pair(service, instance);
        
        auto it = service_sockets_.find(key);
        if (it != service_sockets_.end()) {
            NetworkManager::get_instance().close_socket(it->second);
            service_sockets_.erase(it);
        }
    }
    
    // 回收已结束的客户端处理线程，避免线程句柄在 client_threads_ 中无限堆积。
    // 注意：join 必须在释放 network_mutex_ 之后执行——客户端线程在收尾阶段
    // （handle_client_connection 末尾）也会获取 network_mutex_，若持锁 join 会死锁。
    void reap_finished_client_threads() {
        std::vector<std::thread> to_join;
        {
            std::lock_guard<std::mutex> lock(network_mutex_);
            for (uint64_t conn_id : finished_client_conn_ids_) {
                auto it = client_threads_.find(conn_id);
                if (it != client_threads_.end()) {
                    to_join.push_back(std::move(it->second));
                    client_threads_.erase(it);
                }
            }
            finished_client_conn_ids_.clear();
        }
        for (auto& t : to_join) {
            if (t.joinable()) {
                t.join();
            }
        }
    }

    void handle_client_connection(int client_fd, service_t service, instance_t instance) {
        // 注册网络客户端
        {
            std::lock_guard<std::mutex> lock(network_mutex_);
            network_client_sockets_[client_fd] = client_fd;
        }
        
        // 设置当前线程的网络客户端socket
        current_network_client_fd_ = client_fd;
        
        try {
        while (running_) {
            NetworkMessageHeader header;
            std::vector<uint8_t> payload;
            
            if (!NetworkManager::get_instance().receive_message(client_fd, header, payload)) {
                cgw_sec::SecLogAdapter::facade().warn("sec.network.receive_message_failed",
                    "Failed to receive message",
                    {cgw_sec::slog::f_int("client_fd", client_fd)});
                break;
            }
            
            // 创建消息对象
            std::shared_ptr<Message> message;
            if (header.message_type == static_cast<uint8_t>(message_type_e::RESPONSE) ||
                header.message_type == static_cast<uint8_t>(message_type_e::ERROR)) {
                // 这是响应消息
                message = std::make_shared<Response>();
            } else {
                // 这是请求消息
                message = std::make_shared<Request>();
            }
            
            message->set_service(header.service_id);
            message->set_instance(header.instance_id);
            message->set_method(header.method_id);
            message->set_session(header.session_id);
            message->set_client(header.client_id);
            message->set_message_type(static_cast<message_type_e>(header.message_type));
            message->set_return_code(static_cast<return_code_e>(header.return_code));
            
            if (!payload.empty()) {
                auto payload_obj = std::make_shared<Payload>(payload);
                message->set_payload(payload_obj);
            }
            
            // 如果这是响应消息，找到对应的客户端应用并投递
            if (header.message_type == static_cast<uint8_t>(message_type_e::RESPONSE) ||
                header.message_type == static_cast<uint8_t>(message_type_e::ERROR)) {
                Application* target_app = ServiceRegistry::get_instance().find_application(header.client_id);
                if (target_app) {
                    target_app->enqueue(message);
                } else {
                    cgw_sec::SecLogAdapter::facade().warn("sec.network.no_target_application",
                        "No target application found for response",
                        {cgw_sec::slog::f_str("someip_client_id", cgw_sec::hex_id(header.client_id))});
                }
            } else {
                // 这是请求消息，需要处理并发送响应
                handle_network_request(message, client_fd);
            }
        }
        } catch (const std::exception& e) {
            cgw_sec::SecLogAdapter::facade().error("sec.network.client_connection_exception",
                "Exception in client connection handler",
                {cgw_sec::slog::f_str("error_message", e.what())});
        } catch (...) {
            cgw_sec::SecLogAdapter::facade().error("sec.network.client_connection_exception",
                "Unknown exception in client connection handler");
        }
        
        // 重置当前线程的网络客户端socket
        current_network_client_fd_ = -1;
        
        // 注销网络客户端
        {
            std::lock_guard<std::mutex> lock(network_mutex_);
            network_client_sockets_.erase(client_fd);
        }
        
        NetworkManager::get_instance().close_socket(client_fd);
    }
    
    void connect_to_remote_service(service_t service, instance_t instance) {
        auto& config_mgr = ConfigManager::get_instance();
        ConfigManager::ServiceConfig config;
        if (!config_mgr.get_service_config(service, instance, config)) {
            return;
        }
        
        if (config.tcp_port <= 0) {
            return;
        }
        
        std::lock_guard<std::mutex> lock(network_mutex_);
        auto key = std::make_pair(service, instance);
        if (client_sockets_.find(key) != client_sockets_.end()) {
            return; // 已经连接
        }
        
        int client_fd = NetworkManager::get_instance().create_tcp_client(
            config_mgr.get_unicast_address(), config.tcp_port);
        
        if (client_fd < 0) {
            cgw_sec::SecLogAdapter::facade().error("sec.network.connect_remote_failed",
                "Failed to connect to remote service",
                {cgw_sec::slog::f_str("someip_service_id", cgw_sec::hex_id(service)),
                 cgw_sec::slog::f_str("someip_instance_id", cgw_sec::hex_id(instance))});
            return;
        }
        
        client_sockets_[key] = client_fd;
        
        // 通知服务可用
        ServiceRegistry::get_instance().register_service(service, instance);
        
        cgw_sec::SecLogAdapter::facade().info("sec.network.connected_remote",
            "Connected to remote service",
            {cgw_sec::slog::f_str("someip_service_id", cgw_sec::hex_id(service)),
             cgw_sec::slog::f_str("someip_instance_id", cgw_sec::hex_id(instance)),
             cgw_sec::slog::f_int("someip_port", config.tcp_port)});
    }
    
    bool send_via_network(const std::shared_ptr<Message>& message) {
        std::lock_guard<std::mutex> lock(network_mutex_);
        auto key = std::make_pair(message->get_service(), message->get_instance());
        
        auto it = client_sockets_.find(key);
        if (it == client_sockets_.end()) {
            return false;
        }
        
        auto data = message->serialize_to_network();
        return NetworkManager::get_instance().send_data(it->second, data);
    }
};

// Runtime::create_application 实现
inline std::shared_ptr<Application> Runtime::create_application(const std::string& name) {
    return std::make_shared<Application>(name);
}

} // namespace mock_someip

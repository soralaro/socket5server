#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")

#define SOCKS5_VERSION 0x05
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04

// 辅助函数：将SOCKET转换为字符串用于日志
std::string socket_to_string(SOCKET s) {
    std::stringstream ss;
    ss << s;
    return ss.str();
}

// 线程池类
class ThreadPool {
public:
    ThreadPool(size_t num_threads) : stop(false) {
        std::cout << "ThreadPool initialized with " << num_threads << " worker threads" << std::endl;
        for (size_t i = 0; i < num_threads; ++i) {
            workers.emplace_back([this, i] {
                std::cout << "Worker thread " << i << " started" << std::endl;
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex);
                        this->condition.wait(lock, [this] {
                            return this->stop || !this->tasks.empty();
                        });
                        if (this->stop && this->tasks.empty()) {
                            std::cout << "Worker thread exiting" << std::endl;
                            return;
                        }
                        task = std::move(this->tasks.front());
                        this->tasks.pop();
                        std::cout << "Worker thread picked up a task, remaining tasks: " << this->tasks.size() << std::endl;
                    }
                    task();
                }
            });
        }
    }

    template <class F>
    void enqueue(F&& f) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            tasks.emplace(std::forward<F>(f));
            std::cout << "Task enqueued, total tasks in queue: " << tasks.size() << std::endl;
        }
        condition.notify_one();
    }

    ~ThreadPool() {
        std::cout << "Shutting down thread pool..." << std::endl;
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for (std::thread& worker : workers) {
            worker.join();
        }
        std::cout << "Thread pool shut down complete" << std::endl;
    }

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    std::atomic<bool> stop;
};

// 处理客户端连接的函数
void handle_client(SOCKET client_socket) {
    std::string client_id = socket_to_string(client_socket);
    std::cout << "[" << client_id << "] Starting to handle client connection" << std::endl;

    char buffer[4096];
    int bytes_received;

    // 1. 认证协商
    std::cout << "[" << client_id << "] Waiting for authentication request..." << std::endl;
    bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    
    if (bytes_received == SOCKET_ERROR) {
        std::cerr << "[" << client_id << "] Failed to receive authentication data. Error: " << WSAGetLastError() << std::endl;
        closesocket(client_socket);
        return;
    }
    
    if (bytes_received <= 0) {
        std::cerr << "[" << client_id << "] Client closed connection during authentication phase" << std::endl;
        closesocket(client_socket);
        return;
    }

    std::cout << "[" << client_id << "] Received " << bytes_received << " bytes for authentication" << std::endl;
    
    if (bytes_received < 3 || buffer[0] != SOCKS5_VERSION) {
        std::cerr << "[" << client_id << "] Invalid SOCKS5 version or packet. Expected version 0x05, got 0x" 
                  << std::hex << (int)buffer[0] << std::dec << std::endl;
        closesocket(client_socket);
        return;
    }

    std::cout << "[" << client_id << "] SOCKS5 version confirmed. Supported auth methods count: " << (int)buffer[1] << std::endl;
    
    char auth_response[] = { SOCKS5_VERSION, SOCKS5_AUTH_NONE };
    int send_result = send(client_socket, auth_response, sizeof(auth_response), 0);
    if (send_result == SOCKET_ERROR) {
        std::cerr << "[" << client_id << "] Failed to send auth response. Error: " << WSAGetLastError() << std::endl;
        closesocket(client_socket);
        return;
    }
    std::cout << "[" << client_id << "] Sent authentication response: no authentication required" << std::endl;

    // 2. 请求处理
    std::cout << "[" << client_id << "] Waiting for connection request..." << std::endl;
    bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    
    if (bytes_received == SOCKET_ERROR) {
        std::cerr << "[" << client_id << "] Failed to receive connection request. Error: " << WSAGetLastError() << std::endl;
        closesocket(client_socket);
        return;
    }
    
    if (bytes_received <= 0) {
        std::cerr << "[" << client_id << "] Client closed connection during request phase" << std::endl;
        closesocket(client_socket);
        return;
    }

    std::cout << "[" << client_id << "] Received " << bytes_received << " bytes for connection request" << std::endl;
    
    if (bytes_received < 7 || buffer[0] != SOCKS5_VERSION) {
        std::cerr << "[" << client_id << "] Invalid SOCKS5 version in request. Expected 0x05, got 0x" 
                  << std::hex << (int)buffer[0] << std::dec << std::endl;
        closesocket(client_socket);
        return;
    }

    if (buffer[1] != SOCKS5_CMD_CONNECT) {
        std::cerr << "[" << client_id << "] Unsupported command. Expected CONNECT (0x01), got 0x" 
                  << std::hex << (int)buffer[1] << std::dec << std::endl;
        closesocket(client_socket);
        return;
    }

    // 解析目标地址
    std::string target_address;
    int target_port;
    std::string address_type_str;

    if (buffer[3] == SOCKS5_ATYP_IPV4) {
        address_type_str = "IPv4";
        if (bytes_received < 10) {  // 最小长度检查
            std::cerr << "[" << client_id << "] Incomplete IPv4 address in request" << std::endl;
            closesocket(client_socket);
            return;
        }
        target_address = std::to_string((unsigned char)buffer[4]) + "." +
                         std::to_string((unsigned char)buffer[5]) + "." +
                         std::to_string((unsigned char)buffer[6]) + "." +
                         std::to_string((unsigned char)buffer[7]);
        target_port = (static_cast<unsigned char>(buffer[8]) << 8) | static_cast<unsigned char>(buffer[9]);
    } else if (buffer[3] == SOCKS5_ATYP_DOMAIN) {
        address_type_str = "Domain name";
        if (bytes_received < 7) {  // 最小长度检查
            std::cerr << "[" << client_id << "] Incomplete domain address in request" << std::endl;
            closesocket(client_socket);
            return;
        }
        int domain_length = static_cast<unsigned char>(buffer[4]);
        if (bytes_received < 5 + domain_length + 2) {  // 域名长度 + 2字节端口
            std::cerr << "[" << client_id << "] Domain name truncated in request" << std::endl;
            closesocket(client_socket);
            return;
        }
        target_address.assign(&buffer[5], domain_length);
        target_port = (static_cast<unsigned char>(buffer[5 + domain_length]) << 8) | 
                      static_cast<unsigned char>(buffer[6 + domain_length]);
    } else if (buffer[3] == SOCKS5_ATYP_IPV6) {
        address_type_str = "IPv6";
        std::cerr << "[" << client_id << "] IPv6 addresses are not supported" << std::endl;
        closesocket(client_socket);
        return;
    } else {
        std::cerr << "[" << client_id << "] Unsupported address type: 0x" 
                  << std::hex << (int)buffer[3] << std::dec << std::endl;
        closesocket(client_socket);
        return;
    }

    std::cout << "[" << client_id << "] Parsed " << address_type_str << " target: " 
              << target_address << ":" << target_port << std::endl;

    // 3. 连接目标服务器
    std::cout << "[" << client_id << "] Creating socket for target connection..." << std::endl;
    SOCKET target_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (target_socket == INVALID_SOCKET) {
        std::cerr << "[" << client_id << "] Failed to create target socket for " << target_address << ":" << target_port 
                  << ". Error: " << WSAGetLastError() << std::endl;
        closesocket(client_socket);
        return;
    }
    std::cout << "[" << client_id << "] Target socket created successfully (socket id: " << target_socket << ")" << std::endl;

    sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(target_port);
    memset(&target_addr.sin_zero, 0, sizeof(target_addr.sin_zero));
    
    // 尝试解析域名或直接使用IP地址
    if (inet_pton(AF_INET, target_address.c_str(), &target_addr.sin_addr) != 1) {
        std::cout << "[" << client_id << "] Target is not an IPv4 address, attempting DNS resolution..." << std::endl;
        addrinfo* result = nullptr;
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        
        int getaddrinfo_result = getaddrinfo(target_address.c_str(), nullptr, &hints, &result);
        if (getaddrinfo_result != 0) {
            std::cerr << "[" << client_id << "] Failed to resolve domain " << target_address 
                      << ". Error: " << getaddrinfo_result << " (" << gai_strerrorA(getaddrinfo_result) << ")" << std::endl;
            closesocket(target_socket);
            closesocket(client_socket);
            return;
        }
        
        // 提取解析后的IP地址
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &((sockaddr_in*)result->ai_addr)->sin_addr, ip_str, INET_ADDRSTRLEN);
        std::cout << "[" << client_id << "] Domain " << target_address << " resolved to " << ip_str << std::endl;
        
        target_addr.sin_addr = ((sockaddr_in*)result->ai_addr)->sin_addr;
        freeaddrinfo(result);
    } else {
        std::cout << "[" << client_id << "] Using direct IPv4 address: " << target_address << std::endl;
    }

    std::cout << "[" << client_id << "] Attempting to connect to target " << target_address << ":" << target_port << std::endl;
    if (connect(target_socket, (sockaddr*)&target_addr, sizeof(target_addr)) == SOCKET_ERROR) {
        std::cerr << "[" << client_id << "] Failed to connect to target server " << target_address << ":" << target_port 
                  << ". Error: " << WSAGetLastError() << std::endl;
        closesocket(client_socket);
        closesocket(target_socket);
        return;
    }
    std::cout << "[" << client_id << "] Successfully connected to target server" << std::endl;

    // 4. 发送连接成功响应
    char connect_response[] = { SOCKS5_VERSION, 0x00, 0x00, SOCKS5_ATYP_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    send_result = send(client_socket, connect_response, sizeof(connect_response), 0);
    if (send_result == SOCKET_ERROR) {
        std::cerr << "[" << client_id << "] Failed to send connection response. Error: " << WSAGetLastError() << std::endl;
        closesocket(client_socket);
        closesocket(target_socket);
        return;
    }
    std::cout << "[" << client_id << "] Sent connection success response to client" << std::endl;

    // 5. 数据转发
    std::cout << "[" << client_id << "] Starting data forwarding between client and target" << std::endl;
    fd_set read_fds;
    timeval timeout;
    timeout.tv_sec = 300;  // 5分钟超时
    timeout.tv_usec = 0;
    
    while (true) {
        FD_ZERO(&read_fds);
        FD_SET(client_socket, &read_fds);
        FD_SET(target_socket, &read_fds);

        int activity = select(0, &read_fds, nullptr, nullptr, &timeout);
        if (activity == SOCKET_ERROR) {
            std::cerr << "[" << client_id << "] Select error. Error: " << WSAGetLastError() << std::endl;
            break;
        }
        
        if (activity == 0) {
            std::cout << "[" << client_id << "] Connection timed out after 5 minutes of inactivity" << std::endl;
            break;
        }

        if (FD_ISSET(client_socket, &read_fds)) {
            bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
            if (bytes_received <= 0) {
                if (bytes_received < 0)
                    std::cerr << "[" << client_id << "] Error receiving from client. Error: " << WSAGetLastError() << std::endl;
                else
                    std::cout << "[" << client_id << "] Client closed the connection" << std::endl;
                break;
            }
            
            std::cout << "[" << client_id << "] Received " << bytes_received << " bytes from client, forwarding to target" << std::endl;
            int send_bytes = send(target_socket, buffer, bytes_received, 0);
            if (send_bytes == SOCKET_ERROR) {
                std::cerr << "[" << client_id << "] Failed to send to target. Error: " << WSAGetLastError() << std::endl;
                break;
            }
            if (send_bytes != bytes_received) {
                std::cerr << "[" << client_id << "] Warning: Only sent " << send_bytes << " of " << bytes_received << " bytes" << std::endl;
            }
        }

        if (FD_ISSET(target_socket, &read_fds)) {
            bytes_received = recv(target_socket, buffer, sizeof(buffer), 0);
            if (bytes_received <= 0) {
                if (bytes_received < 0)
                    std::cerr << "[" << client_id << "] Error receiving from target. Error: " << WSAGetLastError() << std::endl;
                else
                    std::cout << "[" << client_id << "] Target server closed the connection" << std::endl;
                break;
            }
            
            std::cout << "[" << client_id << "] Received " << bytes_received << " bytes from target, forwarding to client" << std::endl;
            int send_bytes = send(client_socket, buffer, bytes_received, 0);
            if (send_bytes == SOCKET_ERROR) {
                std::cerr << "[" << client_id << "] Failed to send to client. Error: " << WSAGetLastError() << std::endl;
                break;
            }
            if (send_bytes != bytes_received) {
                std::cerr << "[" << client_id << "] Warning: Only sent " << send_bytes << " of " << bytes_received << " bytes" << std::endl;
            }
        }
    }

    // 清理资源
    std::cout << "[" << client_id << "] Closing connections" << std::endl;
    closesocket(client_socket);
    closesocket(target_socket);
    std::cout << "[" << client_id << "] Client handling complete" << std::endl;
}

int main() {
    std::cout << "Starting SOCKS5 proxy server..." << std::endl;
    
    WSADATA wsaData;
    int wsa_result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsa_result != 0) {
        std::cerr << "WSAStartup failed with error: " << wsa_result << std::endl;
        return 1;
    }
    std::cout << "WSAStartup initialized successfully" << std::endl;

    SOCKET listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket == INVALID_SOCKET) {
        std::cerr << "Failed to create listen socket. Error: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }
    std::cout << "Listen socket created successfully (socket id: " << listen_socket << ")" << std::endl;

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(1080);
    memset(&server_addr.sin_zero, 0, sizeof(server_addr.sin_zero));

    if (bind(listen_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed. Error: " << WSAGetLastError() << std::endl;
        closesocket(listen_socket);
        WSACleanup();
        return 1;
    }
    std::cout << "Socket bound to port 1080 successfully" << std::endl;

    if (listen(listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed. Error: " << WSAGetLastError() << std::endl;
        closesocket(listen_socket);
        WSACleanup();
        return 1;
    }
    std::cout << "SOCKS5 proxy server is running on port 1080, waiting for connections..." << std::endl;

    // 创建线程池，预先分配300个线程
    ThreadPool pool(300);

    while (true) {
        SOCKET client_socket = accept(listen_socket, nullptr, nullptr);
        if (client_socket == INVALID_SOCKET) {
            std::cerr << "Accept failed. Error: " << WSAGetLastError() << std::endl;
            continue;
        }

        std::cout << "New client connected (socket id: " << client_socket << ")" << std::endl;

        // 将客户端连接任务加入线程池
        pool.enqueue([client_socket] {
            handle_client(client_socket);
        });
    }

    // 理论上不会执行到这里
    std::cout << "Shutting down server..." << std::endl;
    closesocket(listen_socket);
    WSACleanup();
    std::cout << "Server shutdown complete" << std::endl;
    return 0;
}
    
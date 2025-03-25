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

#pragma comment(lib, "ws2_32.lib")

#define SOCKS5_VERSION 0x05
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03

// 线程池类
class ThreadPool {
public:
    ThreadPool(size_t num_threads) : stop(false) {
        for (size_t i = 0; i < num_threads; ++i) {
            workers.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex);
                        this->condition.wait(lock, [this] {
                            return this->stop || !this->tasks.empty();
                        });
                        if (this->stop && this->tasks.empty()) {
                            return;
                        }
                        task = std::move(this->tasks.front());
                        this->tasks.pop();
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
        }
        condition.notify_one();
    }

    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for (std::thread& worker : workers) {
            worker.join();
        }
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
    char buffer[256];
    int bytes_received;

    // 1. 认证协商
    bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received < 3 || buffer[0] != SOCKS5_VERSION) {
        std::cerr << "Invalid SOCKS5 version or packet." << std::endl;
        closesocket(client_socket);
        return;
    }

    char auth_response[] = { SOCKS5_VERSION, SOCKS5_AUTH_NONE };
    send(client_socket, auth_response, sizeof(auth_response), 0);

    // 2. 请求处理
    bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received < 7 || buffer[0] != SOCKS5_VERSION || buffer[1] != SOCKS5_CMD_CONNECT) {
        std::cerr << "Invalid SOCKS5 request." << std::endl;
        closesocket(client_socket);
        return;
    }

    // 解析目标地址
    std::string target_address;
    int target_port;
    if (buffer[3] == SOCKS5_ATYP_IPV4) {
        target_address = std::to_string((unsigned char)buffer[4]) + "." +
                         std::to_string((unsigned char)buffer[5]) + "." +
                         std::to_string((unsigned char)buffer[6]) + "." +
                         std::to_string((unsigned char)buffer[7]);
        target_port = (buffer[8] << 8) | buffer[9];
    } else if (buffer[3] == SOCKS5_ATYP_DOMAIN) {
        int domain_length = buffer[4];
        target_address.assign(&buffer[5], domain_length);
        target_port = (buffer[5 + domain_length] << 8) | buffer[6 + domain_length];
    } else {
        std::cerr << "Unsupported address type." << std::endl;
        closesocket(client_socket);
        return;
    }

    // 3. 连接目标服务器
    SOCKET target_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (target_socket == INVALID_SOCKET) {
        std::cerr << "Failed to create target socket." << std::endl;
        closesocket(client_socket);
        return;
    }

    sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(target_port);
    inet_pton(AF_INET, target_address.c_str(), &target_addr.sin_addr);

    if (connect(target_socket, (sockaddr*)&target_addr, sizeof(target_addr)) == SOCKET_ERROR) {
        std::cerr << "Failed to connect to target server." << std::endl;
        closesocket(client_socket);
        closesocket(target_socket);
        return;
    }

    // 4. 发送连接成功响应
    char connect_response[] = { SOCKS5_VERSION, 0x00, 0x00, SOCKS5_ATYP_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    send(client_socket, connect_response, sizeof(connect_response), 0);

    // 5. 数据转发
    fd_set read_fds;
    while (true) {
        FD_ZERO(&read_fds);
        FD_SET(client_socket, &read_fds);
        FD_SET(target_socket, &read_fds);

        int activity = select(0, &read_fds, nullptr, nullptr, nullptr);
        if (activity == SOCKET_ERROR) {
            std::cerr << "Select error." << std::endl;
            break;
        }

        if (FD_ISSET(client_socket, &read_fds)) {
            bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
            if (bytes_received <= 0) break;
            send(target_socket, buffer, bytes_received, 0);
        }

        if (FD_ISSET(target_socket, &read_fds)) {
            bytes_received = recv(target_socket, buffer, sizeof(buffer), 0);
            if (bytes_received <= 0) break;
            send(client_socket, buffer, bytes_received, 0);
        }
    }

    closesocket(client_socket);
    closesocket(target_socket);
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return 1;
    }

    SOCKET listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket == INVALID_SOCKET) {
        std::cerr << "Failed to create listen socket." << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(1080);

    if (bind(listen_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed." << std::endl;
        closesocket(listen_socket);
        WSACleanup();
        return 1;
    }

    if (listen(listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed." << std::endl;
        closesocket(listen_socket);
        WSACleanup();
        return 1;
    }

    std::cout << "SOCKS5 proxy server is running on port 1080..." << std::endl;

    // 创建线程池，预先分配300个线程
    ThreadPool pool(300);

    while (true) {
        SOCKET client_socket = accept(listen_socket, nullptr, nullptr);
        if (client_socket == INVALID_SOCKET) {
            std::cerr << "Accept failed." << std::endl;
            continue;
        }

        std::cout << "New client connected." << std::endl;

        // 将客户端连接任务加入线程池
        pool.enqueue([client_socket] {
            handle_client(client_socket);
        });
    }

    closesocket(listen_socket);
    WSACleanup();
    return 0;
}

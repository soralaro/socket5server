#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <poll.h>

#define SOCKS5_VERSION 0x05
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03

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
                        if (this->stop && this->tasks.empty()) return;
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

void handle_client(int client_socket) {
    char buffer[256];
    int bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received < 3 || buffer[0] != SOCKS5_VERSION) {
        close(client_socket);
        return;
    }

    char auth_response[] = { SOCKS5_VERSION, SOCKS5_AUTH_NONE };
    send(client_socket, auth_response, sizeof(auth_response), 0);
    bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received < 7 || buffer[0] != SOCKS5_VERSION || buffer[1] != SOCKS5_CMD_CONNECT) {
        close(client_socket);
        return;
    }

    std::string target_address;
    int target_port;
    if (buffer[3] == SOCKS5_ATYP_IPV4) {
        target_address = inet_ntoa(*(in_addr*)&buffer[4]);
        target_port = (buffer[8] << 8) | buffer[9];
    } else {
        close(client_socket);
        return;
    }

    int target_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (target_socket == -1) {
        close(client_socket);
        return;
    }

    sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(target_port);
    inet_pton(AF_INET, target_address.c_str(), &target_addr.sin_addr);

    if (connect(target_socket, (sockaddr*)&target_addr, sizeof(target_addr)) == -1) {
        close(client_socket);
        close(target_socket);
        return;
    }

    char connect_response[] = { SOCKS5_VERSION, 0x00, 0x00, SOCKS5_ATYP_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    send(client_socket, connect_response, sizeof(connect_response), 0);

    struct pollfd fds[2] = {
        { client_socket, POLLIN, 0 },
        { target_socket, POLLIN, 0 }
    };

    while (true) {
        int ret = poll(fds, 2, -1);
        if (ret <= 0) break;

        if (fds[0].revents & POLLIN) {
            bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
            if (bytes_received <= 0) break;
            send(target_socket, buffer, bytes_received, 0);
        }

        if (fds[1].revents & POLLIN) {
            bytes_received = recv(target_socket, buffer, sizeof(buffer), 0);
            if (bytes_received <= 0) break;
            send(client_socket, buffer, bytes_received, 0);
        }
    }

    close(client_socket);
    close(target_socket);
}

int main() {
    int listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_socket == -1) {
        std::cerr << "Failed to create listen socket." << std::endl;
        return 1;
    }

    sockaddr_in server_addr = { AF_INET, htons(1082), INADDR_ANY };
    if (bind(listen_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        std::cerr << "Bind failed." << std::endl;
        close(listen_socket);
        return 1;
    }

    if (listen(listen_socket, SOMAXCONN) == -1) {
        std::cerr << "Listen failed." << std::endl;
        close(listen_socket);
        return 1;
    }

    std::cout << "SOCKS5 proxy server is running on port 1082..." << std::endl;
    ThreadPool pool(300);

    while (true) {
        int client_socket = accept(listen_socket, nullptr, nullptr);
        if (client_socket == -1) {
            std::cerr << "Accept failed." << std::endl;
            continue;
        }
        pool.enqueue([client_socket] { handle_client(client_socket); });
    }

    close(listen_socket);
    return 0;
}



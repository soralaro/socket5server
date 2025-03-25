#for windows

g++ -o socket5m.exe socket5_mutilethreads_windows.cpp -lws2_32

#for linux

g++ -std=c++11 -pthread socks5_proxy.cpp -o socks5_proxy

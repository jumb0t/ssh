rm -rf *.log
rm -rf socks5proxy
g++ -std=c++20 socks5ssh.cpp -o socks5proxy -O3 -lboost_system -lssh -lpthread -I /usr/include/nlohmann

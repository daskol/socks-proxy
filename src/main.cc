/**
 *  \file main.cc
 */

#include <socks4.h>

#include <memory>

#include <glog/logging.h>

int main(int, char* argv[]) {
    google::InitGoogleLogging(argv[0]);

    auto address = boost::asio::ip::address_v4::from_string("127.0.0.1");
    boost::asio::ip::tcp::endpoint endpoint(address, 1080);
    boost::asio::io_service io_service;
    boost::posix_time::time_duration timeout(0, 0, 1, 0); // one second

    auto proxy = std::make_shared<Socks4Proxy>(io_service, endpoint, timeout);
    proxy->run();

    io_service.run();

    return 0;
}

/**
 *  \file main.cc
 */

#include <memory>

#include <glog/logging.h>

#include <acl.h>
#include <socks4.h>
#include <socks5.h>

int main(int argc, char* argv[]) {
    google::InitGoogleLogging(argv[0]);

    if (argc != 2) {
        LOG(ERROR) << "No password file.";
        return 1;
    }

    ACL acl = ACL::load(argv[1]);

    auto address = boost::asio::ip::address_v4::from_string("127.0.0.1");
    boost::asio::ip::tcp::endpoint endpoint(address, 1080);
    boost::asio::io_context io;
    boost::posix_time::time_duration timeout(0, 0, 1, 0); // one second

    auto proxy = std::make_shared<Socks5Proxy>(io, endpoint, timeout, acl);
    proxy->run();

    io.run();

    return 0;
}

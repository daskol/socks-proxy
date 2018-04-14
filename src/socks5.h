/**
 *  \file socks5.h
 */

#pragma once

#include <memory>
#include <boost/asio.hpp>

class Socks5Proxy : public std::enable_shared_from_this<Socks5Proxy> {
public:
    Socks5Proxy(boost::asio::io_service& io_service,
                boost::asio::ip::tcp::endpoint at,
                boost::posix_time::time_duration timeout);

    ~Socks5Proxy(void);

    void run(void);
    void stop(void);
};

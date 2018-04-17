/**
 *  \file socks4.h
 */

#pragma once

#include <cstdint>

#ifdef NDEBUG
#define BOOST_ASIO_ENABLE_HANDLER_TRACKING
#endif

#include <boost/asio.hpp>
#include <glog/logging.h>

#pragma pack(push, 1)

struct Hello {
    uint8_t version;
    uint8_t command;
    uint16_t dst_port;
    uint32_t dst_ip;
};

#pragma pack(pop)

struct ProxyParams {
    boost::asio::ip::tcp::endpoint endpoint;
    std::string user;
};

void Socks4Handshake(boost::asio::ip::tcp::socket& conn,
                     const boost::asio::ip::tcp::endpoint& addr,
                     const std::string& user);

void ConnectProxyChain(boost::asio::ip::tcp::socket& socket,
                       const std::vector<ProxyParams>& proxy_chain,
                       boost::asio::ip::tcp::endpoint destination);

constexpr size_t operator""_kb(unsigned long long kilobytes) {
    return kilobytes * 1024;  // bytes
}

class Session : public std::enable_shared_from_this<Session> {
    static constexpr size_t m_buffer_size = 4_kb;

public:
    Session(boost::asio::ip::tcp::socket socket,
            boost::posix_time::time_duration timeout)
        : m_src(std::move(socket))
        , m_dst(m_src.get_io_service())
        , m_timeout(timeout)
        , m_cli_timer(m_src.get_io_service())
        , m_srv_timer(m_src.get_io_service())
        , m_cli2srv{new uint8_t[4_kb]}
        , m_srv2cli{new uint8_t[4_kb]} {}

    void init(void) noexcept;

private:
    void doConnect(size_t size) noexcept;
    void doRecvHello(void) noexcept;
    void doSendHello(uint8_t command) noexcept;
    void doRecvUserID(size_t size) noexcept;

    void doRecvFromClient(void) noexcept;
    void doSendToClient(size_t size) noexcept;

    void doRecvFromServer(void) noexcept;
    void doSendToServer(size_t size) noexcept;

    void onTimeout(boost::system::error_code ec, bool client) noexcept;

    void setupClientTimeout(void) noexcept;
    void setupServerTimeout(void) noexcept;

    void moveMemory(uint8_t* begin, uint8_t* end) noexcept;
    uint8_t* findUserID(uint8_t* begin, uint8_t* end) noexcept;

private:
    boost::asio::ip::tcp::socket m_src;
    boost::asio::ip::tcp::socket m_dst;
    boost::posix_time::time_duration m_timeout;

    boost::asio::deadline_timer m_cli_timer;
    boost::asio::deadline_timer m_srv_timer;

    std::unique_ptr<uint8_t[]> m_cli2srv;  // cli -> proxy -> srv
    std::unique_ptr<uint8_t[]> m_srv2cli;  // srv -> proxy -> cli

    std::string m_user_id;
    Hello m_hello;
};

class Socks4Proxy : public std::enable_shared_from_this<Socks4Proxy> {
public:
    Socks4Proxy(boost::asio::io_service& io_service,
                boost::asio::ip::tcp::endpoint at,
                boost::posix_time::time_duration timeout)
        : m_acceptor(io_service, at)
        , m_timeout(timeout) {}

    ~Socks4Proxy() {
        m_acceptor.get_io_service().stop();
    }

    void run(void) noexcept;
    void startAccept(void) noexcept;

private:
    boost::asio::ip::tcp::acceptor m_acceptor;
    boost::posix_time::time_duration m_timeout;
};

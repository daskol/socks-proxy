/**
 *  \file socks5.h
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <memory>

#include <boost/asio.hpp>

#include <acl.h>

enum Version : uint8_t {
    SOCKS4 = 0x04,
    SOCKS5 = 0x05,
};

enum AuthMethod : uint8_t {
    NOAUTH = 0x00,
    GSSAPI = 0x01,
    PASSWORD = 0x02,
    NO_ACCEPTABLE = 0xff,
};

enum Command : uint8_t {
    CONNECT = 0x01,
    BIND = 0x02,
    UDP_ASSOCIATE = 0x03,
};

enum Reply : uint8_t {
    SUCCEEDED = 0x00,
    FAILURE = 0x01,
    NOT_ALLOWED = 0x02,
    NETWORK_UNREACHABLE = 0x03,
    HOST_UNREACHABLE = 0x04,
    CONNECTION_REFUSED = 0x05,
    TTL_EXPIRED = 0x06,
    COMMAND_NOT_SUPPORTED = 0x07,
    ADDRESS_NOT_SUPPORTED = 0x08,
};

enum AddressType : uint8_t {
    AT_IPV4 = 0x01,
    AT_FQDN = 0x03,
    AT_IPV6 = 0x04,
};

#pragma pack(push, 1)

struct SubNegotiationRequest {
    Version    version;
    uint8_t         nomethods;
    AuthMethod      methods[1];
};

struct SubNegotiationResponse {
    Version    version;
    AuthMethod      method;
};

struct IPv4 {
    uint32_t ip;
    uint16_t port;
};

typedef uint8_t uint128_t[8];

struct IPv6 {
    uint128_t   ip;
    uint16_t    port;
};

struct FQDN {
    uint8_t bytes[4];
};

union Destination {
    IPv4 ipv4;
    IPv6 ipv6;
    FQDN fqdn;
};

struct NegotiationRequest {
    Version    version;
    Command    command;
    uint8_t         reserverd;
    AddressType     addr_type;
    Destination     dest;
};

struct NegotiationReply {
    Version    version;
    Reply      reply;
    uint8_t         reserverd;
    AddressType     addr_type;
    Destination     dest;
};

#pragma pack(pop)

struct UserPassRequest {
    Version version;
    std::string username;
    std::string password;
};

class Socks5Session : public std::enable_shared_from_this<Socks5Session> {
public:
    Socks5Session(boost::asio::ip::tcp::socket socket,
                  boost::posix_time::time_duration timeout)
        : m_src(std::move(socket))
        , m_dst(m_src.get_io_service())
        , m_timeout(timeout) {}

    void init(void) noexcept;

private:
    void doRecvSubNegotiation(void) noexcept;
    void doSendSubNegotiation(void) noexcept;

    void doRecvNegotiation(void) noexcept;
    void doSendNegotiation(void) noexcept;

    void doRecvFromClient(void) noexcept;
    void doSendToServer(size_t size) noexcept;

    void doRecvFromServer(void) noexcept;
    void doSendToClient(size_t size) noexcept;

private:
    boost::asio::ip::tcp::socket m_src;
    boost::asio::ip::tcp::socket m_dst;
    boost::posix_time::time_duration m_timeout;
};

class Socks5Proxy : public std::enable_shared_from_this<Socks5Proxy> {
public:
    Socks5Proxy(boost::asio::io_service& io_service,
                boost::asio::ip::tcp::endpoint at,
                boost::posix_time::time_duration timeout,
                const ACL &acl)
        : m_acceptor(io_service, at)
        , m_timeout(timeout)
        , m_acl{acl} {}

    ~Socks5Proxy(void) {
        m_acceptor.get_io_service().stop();
    }

    void run(void);
    void stop(void);

private:
    boost::asio::ip::tcp::acceptor m_acceptor;
    boost::posix_time::time_duration m_timeout;

    const ACL m_acl;
};

/**
 *  \file socks5.h
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <memory>

#include <boost/asio.hpp>

#include <acl.h>
#include <common.h>

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

enum Status : uint8_t {
    SUCCESS = 0x00,
    FORBIDDEN = 0x01,
};

enum AddressType : uint8_t {
    AT_IPV4 = 0x01,
    AT_FQDN = 0x03,
    AT_IPV6 = 0x04,
};

#pragma pack(push, 1)

struct SubNegotiationRequest {
    Version         version;
    uint8_t         nomethods;
    AuthMethod      methods[1];
};

struct SubNegotiationResponse {
    Version         version;
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
    Version         version;
    Command         command;
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

struct AuthStatusResponse {
    Version version;
    Status  status;
};

class UsernamePasswordNegotiator
    : public std::enable_shared_from_this<UsernamePasswordNegotiator> {

    static constexpr uint8_t m_version = 0x01;  // subnegotiation version

public:
    typedef std::function<void(bool)> handler_t;

    UsernamePasswordNegotiator(boost::asio::ip::tcp::socket &socket,
                               const ACL &acl,
                               uint8_t *buffer,
                               size_t size,
                               size_t capacity) noexcept
        : m_username{}
        , m_password{}
        , m_acl{acl}
        , m_socket{socket}
        , m_handler{nullptr}
        , m_data{buffer}
        , m_size{size}
        , m_capacity{capacity} {}

    void negotiate(handler_t handler) noexcept;

private:
    void recvHeader(void) noexcept;
    void recvUsername(void) noexcept;
    void recvPassword(void) noexcept;
    void sendStatus(void) noexcept;

private:
    std::string m_username;
    std::string m_password;

    const ACL &m_acl;
    boost::asio::ip::tcp::socket &m_socket;
    handler_t m_handler;

    uint8_t *m_data;
    size_t m_size;
    size_t m_capacity;
};

class Socks5Session : public std::enable_shared_from_this<Socks5Session> {
    using error_code = boost::system::error_code;

public:
    Socks5Session(boost::asio::ip::tcp::socket socket,
                  boost::posix_time::time_duration timeout,
                  const ACL &acl)
        : m_src(std::move(socket))
        , m_dst(m_src.get_io_service())
        , m_timeout(timeout)
        , m_input_buffer{new uint8_t[4_kb]}
        , m_input_size{0}
        , m_acl{acl} {}

    void init(void) noexcept;

private:
    void recvSubNegotiation(const error_code &, size_t) noexcept;
    void sendSubNegotiation(const error_code &) noexcept;

    void recvNegotiation(void) noexcept;
    void sendNegotiation(void) noexcept;

    void recvUserPass(const error_code &, size_t) noexcept;

    void recvFromClient(void) noexcept;
    void sendToServer(size_t size) noexcept;

    void recvFromServer(void) noexcept;
    void sendToClient(size_t size) noexcept;

    AuthMethod getSupportedMethod(const AuthMethod *, size_t) const noexcept;

private:
    boost::asio::ip::tcp::socket m_src;
    boost::asio::ip::tcp::socket m_dst;
    boost::posix_time::time_duration m_timeout;

    std::unique_ptr<uint8_t[]> m_input_buffer;
    size_t m_input_size;

    const ACL &m_acl;
};

class Socks5Proxy : public std::enable_shared_from_this<Socks5Proxy> {
    using error_code = boost::system::error_code;
    using tcp = boost::asio::ip::tcp;

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
    void accept(const error_code &, tcp::socket) noexcept;

private:
    boost::asio::ip::tcp::acceptor m_acceptor;
    boost::posix_time::time_duration m_timeout;

    const ACL &m_acl;
};

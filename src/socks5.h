/**
 *  \file socks5.h
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <memory>
#include <boost/asio.hpp>

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

class Socks5Proxy : public std::enable_shared_from_this<Socks5Proxy> {
public:
    Socks5Proxy(boost::asio::io_service& io_service,
                boost::asio::ip::tcp::endpoint at,
                boost::posix_time::time_duration timeout);

    ~Socks5Proxy(void);

    void run(void);
    void stop(void);
};

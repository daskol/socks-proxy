/**
 *  \file socks5.cc
 */

#include <socks5.h>
#include <memory>
#include <glog/logging.h>

using boost::asio::async_read;
using boost::asio::buffer;
using boost::asio::mutable_buffer;
using boost::asio::ip::tcp;
using boost::system::error_code;

char nibble2char(uint8_t value) noexcept {
    if (0 <= value && value < 10) {
        return 0x30 + value;
    } else {
        return 0x60 + (value - 0x09);
    }
}

std::string uint8tochar(uint8_t value) noexcept {
    std::string segment;
    uint8_t lo = value & 0x0f, hi = (value >> 4) & 0x0f;
    return {nibble2char(hi), nibble2char(lo)};
}

std::ostream &operator << (std::ostream &os, const IPv4 &addr) {
    union {
        uint32_t ip;
        uint8_t  octets[4];
    };

    ip = addr.ip;
    os << (int)octets[0] << '.'
       << (int)octets[1] << '.'
       << (int)octets[2] << '.'
       << (int)octets[3] << ':'
       << addr.port;

    return os;
}

std::ostream &operator << (std::ostream &os, const IPv6 &addr) {
    for (size_t i = 0; i != sizeof(IPv6::ip); i++) {
        int octet1 = addr.ip[i];
        int octet2 = addr.ip[++i];
        int segment = (octet1 << 8) + octet2;

        os << std::hex << segment << ':';
    }

    return os << addr.port;
}

void UsernamePasswordNegotiator::negotiate(handler_t handler) noexcept {
    LOG(INFO) << "Launch username/password auth negotiation";
    m_handler = handler;
    recvHeader();
}

void UsernamePasswordNegotiator::recvHeader(void) noexcept {
    LOG(INFO) << "Recieve and check header: size=" << m_size
              << "/" << m_capacity;

    if (m_size < sizeof(uint8_t)) {
        auto that = shared_from_this();
        m_socket.async_read_some(buffer(m_data + m_size, m_capacity - m_size),
                                 [this, that] (auto &ec, size_t size) {
            if (ec) {
                LOG(ERROR) << "Failed to read some bytes: [" << ec.value()
                           << "] " << ec.message();
                m_handler(false);
            } else {
                m_size += size;
                recvHeader();
            }
        });
    } else if (m_data[0] != m_version) {
        LOG(INFO) << "version = " << (int)m_data[0];
        m_handler(false);
    } else {
        recvUsername();
    }
}

void UsernamePasswordNegotiator::recvUsername(void) noexcept {
    LOG(INFO) << "Recieving username";

    size_t expected = 2 * sizeof(uint8_t);

    if (m_size >= expected && m_size >= expected + m_data[1]) {
        m_username = std::string(m_data + 2, m_data + expected + m_data[1]);
        recvPassword();
    } else {
        auto that = shared_from_this();
        m_socket.async_read_some(buffer(m_data + m_size, m_capacity - m_size),
                                 [this, that] (auto &ec, size_t size) {
            if (ec) {
                LOG(ERROR) << "Failed to read some bytes: [" << ec.value()
                           << "] " << ec.message();
                m_handler(false);
            } else {
                m_size += size;
                recvUsername();
            }
        });
    }
}

void UsernamePasswordNegotiator::recvPassword(void) noexcept {
    LOG(INFO) << "Recieving password";

    size_t expected = 3 * sizeof(uint8_t) + m_data[1];
    size_t length = m_data[expected - 1];

    if (m_size >= expected && m_size == expected + length) {
        uint8_t *begin = m_data + expected;
        uint8_t *end = m_data + expected + length;
        m_password = std::string(begin, end);
        sendStatus();
    } else if (m_size >= expected + length) {
        LOG(INFO) << "wrong auth username/password request";
        m_handler(false);
    }
}

void UsernamePasswordNegotiator::sendStatus(void) noexcept {
    LOG(INFO) << "Recieved username=" << m_username
              << "; password=" << m_password << ";";

    bool status = m_acl.find(m_username + ":" + m_password);

    struct {
        uint8_t version;
        uint8_t status;
    } response;

    response.version = m_version;
    response.status = status ? Status::SUCCESS : Status::FORBIDDEN;

    auto that = shared_from_this();
    auto buf = buffer(&response, 2 * sizeof(uint8_t));

    async_write(m_socket, buf, [this, that, status] (auto &ec, size_t size) {
        if (ec) {
            LOG(ERROR) << "Failed write auth status: [" << ec.value()
                       << "] " << ec.message();
            m_handler(false);
        } else {
            m_handler(status);
        }
    });
}

void Socks5Session::init(void) noexcept {
    LOG(INFO) << "Instantiate socks5 session for incomming connection "
               << m_src.remote_endpoint();

    auto that = shared_from_this();
    auto buf = buffer(m_input_buffer.get(), 3);

    async_read(m_src, std::move(buf), [this, that] (auto &ec, size_t size) {
        recvSubNegotiation(ec, size);
    });
}

void Socks5Session::recvSubNegotiation(const error_code &ec,
                                       size_t bytes_transfered) noexcept {
    LOG(INFO) << "Recieving " << bytes_transfered
              << " byte(s) during subnegotiation";

    m_input_size += bytes_transfered;

    auto that = shared_from_this();
    auto req = (SubNegotiationRequest *)m_input_buffer.get();
    size_t expected_size = sizeof(SubNegotiationRequest) + req->nomethods - 1;

    if (req->version != Version::SOCKS5) {
        LOG(INFO) << "Close connection: wrong version number: "
                  << (unsigned)req->version;
    } else if (m_input_size == expected_size) {
        auto method = getSupportedMethod(req->methods, req->nomethods);
        auto res = (SubNegotiationResponse *)m_input_buffer.get();

        res->version = Version::SOCKS5;
        res->method = method;

        auto size = sizeof(SubNegotiationResponse);
        auto buf = buffer(m_input_buffer.get(), size);

        async_write(m_src, std::move(buf), [this, that] (auto &ec, auto) {
            sendSubNegotiation(ec);
        });
    } else if (m_input_size == 4_kb) {
        LOG(INFO) << "Close connection: wrong subnegotiation request";
    } else {
        auto ptr = m_input_buffer.get() + m_input_size;
        auto buf = buffer(ptr, expected_size - m_input_size);

        async_read(m_src, std::move(buf), [this, that] (auto &ec, auto size) {
            recvSubNegotiation(ec, size);
        });
    }
}

void Socks5Session::sendSubNegotiation(const error_code &ec) noexcept {
    LOG(INFO) << "Sending subnegotiation response";

    auto res = (SubNegotiationResponse *)m_input_buffer.get();

    if (res->method == AuthMethod::NO_ACCEPTABLE) {
        error_code ec;
        m_src.close(ec);

        if (ec) {
            LOG(ERROR) << "Close incoming connection: [" << ec.value()
                       << "] " << ec.message();
        }
        return;
    }

    m_input_size = 0;

    auto buf = mutable_buffer(m_input_buffer.get(), 4_kb);
    auto that = shared_from_this();

    m_src.async_read_some(std::move(buf), [this, that] (auto &ec, auto size) {
        authorize(ec, size);
    });
}

void Socks5Session::authorize(const error_code &ec,
                              size_t bytes_transfered) noexcept {
    LOG(INFO) << "Recieving " << bytes_transfered
              << " bytes for username/password auth";

    m_input_size += bytes_transfered;

    auto that = shared_from_this();
    auto ptr = m_input_buffer.get();
    auto neg = std::make_shared<UsernamePasswordNegotiator>(
        m_src, m_acl, ptr, m_input_size, 4_kb
    );

    neg->negotiate([this, that, neg] (bool status) {
        LOG(INFO) << "Access " << (status ? "granted" : "denied");

        if (!status) {
            // TODO: close socket connection.
            error_code ec;
            m_src.close(ec);

            if (ec) {
                LOG(ERROR) << "Failed to close socket: [" << ec.value()
                           << "] " << ec.message();
            }
        } else {
            m_input_size = 0;
            recvNegotiation();
        }
    });
}

void Socks5Session::recvNegotiation(void) noexcept {
    LOG(INFO) << "Start connection negotiation";

    // https://tools.ietf.org/html/rfc1928#section-4
    recvNegotiationHeader();
}

void Socks5Session::recvNegotiationHeader(void) noexcept {
    size_t expected = sizeof(Version) + sizeof(Command) +
                      sizeof(uint8_t) + sizeof(AddressType);

    auto buf = mutable_buffer(m_input_buffer.get(), expected);
    auto that = shared_from_this();

    async_read(m_src, std::move(buf), [this, that] (auto &ec, auto size) {
        if (ec) {
            LOG(ERROR) << "Failed to read header of negotiation request: ["
                       << ec.value() << "] " << ec.message();
            return;
        }

        auto *ptr = m_input_buffer.get();
        auto *req = reinterpret_cast<NegotiationRequest *>(ptr);

        if (req->version != Version::SOCKS5) {
            LOG(ERROR) << "Wrong socks protocol version in negotiation";
            return;
        }

        switch (req->command) {
        case Command::CONNECT:
            break;
        case Command::BIND:
        case Command::UDP_ASSOCIATE:
            LOG(ERROR) << "Negotiation request command is not implemented yet";
            return;
        default:
            LOG(ERROR) << "Wrong negotiation request command: " << req->command;
            return;
        }

        switch (req->addr_type) {
        case AddressType::AT_IPV4:
            recvIPv4Address();
        case AddressType::AT_IPV6:
            recvIPv6Address();
        default:
            LOG(ERROR) << "Unsupported address type: " << req->addr_type;
        }

    });
}

void Socks5Session::recvIPv4Address(void) noexcept {
    size_t expected = sizeof(IPv4);

    auto buf = mutable_buffer(m_input_buffer.get(), expected);
    auto that = shared_from_this();

    async_read(m_src, std::move(buf), [this, that] (auto &ec, auto size) {
        if (ec) {
            LOG(ERROR) << "Failed to read request destination: ["
                       << ec.value() << "] " << ec.message();
            return;
        }

        auto *ipv4 = reinterpret_cast<IPv4 *>(m_input_buffer.get());

        ipv4->port = ((ipv4->port & 0xff00) >> 8 |
                      (ipv4->port & 0x00ff) << 8);

        LOG(INFO) << "Address is " << *ipv4;
    });
}

void Socks5Session::recvIPv6Address(void) noexcept {
    size_t expected = sizeof(IPv6);

    auto buf = mutable_buffer(m_input_buffer.get(), expected);
    auto that = shared_from_this();

    async_read(m_src, std::move(buf), [this, that] (auto &ec, auto size) {
        if (ec) {
            LOG(ERROR) << "Failed to read request destination: ["
                       << ec.value() << "] " << ec.message();
            return;
        }

        auto *ipv6 = reinterpret_cast<IPv6 *>(m_input_buffer.get());
        auto &ip = ipv6->ip;

        ipv6->port = ((ipv6->port & 0xff00) >> 8 |
                      (ipv6->port & 0x00ff) << 8);

        LOG(INFO) << "IPv6 address is " << *ipv6;

        boost::asio::ip::address_v6 addr({
            ip[0], ip[1], ip[2],  ip[3],  ip[4],  ip[5],  ip[6],  ip[7],
            ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15],
        });
        boost::asio::ip::tcp::endpoint endpoint(addr, ipv6->port);

        connect(endpoint);
    });
}

void Socks5Session::connect(const tcp::endpoint &endpoint) noexcept {
    LOG(INFO) << "Connect to SOCKS server at " << endpoint;

    auto that =  shared_from_this();

    m_dst.async_connect(endpoint, [this, that, endpoint] (auto ec) {
        if (ec) {
            LOG(ERROR) << "Failed to connect to server at " << endpoint
                       << ": [" << ec.value() << "] " << ec.message();
            return;
        }

        sendNegotiation();
    });
}

void Socks5Session::sendNegotiation(void) noexcept {
    LOG(INFO) << "Send negotiation response";

    auto endpoint = m_dst.local_endpoint();
    auto addr = endpoint.address();
    auto res = reinterpret_cast<NegotiationResponse *>(m_input_buffer.get());

    res->version = Version::SOCKS5;
    res->reply = Reply::SUCCEEDED;
    res->reserved = 0;

    uint16_t port = endpoint.port();
    size_t offset = sizeof(Version) + sizeof(Command) +
                    sizeof(uint8_t) + sizeof(AddressType);

    LOG(INFO) << "Local endpoint is " << endpoint;

    if (addr.is_v4()) {
        res->addr_type = AddressType::AT_IPV4;

        auto ptr = m_input_buffer.get();
        auto ip = addr.to_v4().to_bytes();

        std::copy(ip.begin(), ip.end(), ptr + offset);
        offset += ip.size();

        ptr[offset + 0] = (port & 0x00ff) >> 0;
        ptr[offset + 1] = (port & 0xff00) >> 8;
        offset += sizeof(port);
    } else {
        res->addr_type = AddressType::AT_IPV6;

        auto ptr = m_input_buffer.get();
        auto ip = addr.to_v6().to_bytes();

        std::copy(ip.begin(), ip.end(), ptr + offset);
        offset += ip.size();

        ptr[offset + 0] = (port & 0x00ff) >> 0;
        ptr[offset + 1] = (port & 0xff00) >> 8;
        offset += sizeof(port);
    }

    auto ptr = m_input_buffer.get();
    auto buf = buffer(m_input_buffer.get(), offset);
    auto that = shared_from_this();

    std::string str;

    for (size_t i = 0; i != offset; ++i) {
        str += "\\x" + uint8tochar(ptr[i]);
    }

    LOG(INFO) << "negotiation response is res = '" << str << "'";

    async_write(m_src, buf, [this, that] (auto ec, auto size) {
        if (ec) {
            LOG(ERROR) << "Failed to send negotiation response: ["
                       << ec.value() << "] " << ec.message();
            return;
        }

        LOG(INFO) << "Start bidirectional retransmission"; // TODO(@daskol)
    });
}

AuthMethod Socks5Session::getSupportedMethod(const AuthMethod *methods,
                                             size_t nomethods) const noexcept {
    for (size_t i = 0; i != nomethods; ++i) {
        if (methods[i] == AuthMethod::PASSWORD) {
            return AuthMethod::PASSWORD;
        }
    }

    return AuthMethod::NO_ACCEPTABLE;
}

void Socks5Proxy::run(void) {
    auto that = shared_from_this();
    m_acceptor.async_accept(
        [this, that] (const error_code &ec, tcp::socket &&socket) {
            accept(ec, std::move(socket));
    });
}

void Socks5Proxy::accept(const error_code &ec, tcp::socket sock) noexcept {
    if (ec) {
        LOG(ERROR) << "Proxy failed to accept connection: [" << ec.value()
                   << "] " << ec.message();
        return;
    }

    LOG(INFO) << "Accept connection from `" << sock.remote_endpoint() << "`";

    auto that = shared_from_this();
    auto session = std::make_shared<Socks5Session>(std::move(sock),
                                                   m_timeout, m_acl);

    session->init();

    m_acceptor.async_accept(
        [this, that] (const error_code &ec, tcp::socket &&socket) {
            accept(ec, std::move(socket));
    });
}

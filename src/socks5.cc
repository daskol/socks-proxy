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
        recvUserPass(ec, size);
    });
}

void Socks5Session::recvUserPass(const error_code &ec,
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

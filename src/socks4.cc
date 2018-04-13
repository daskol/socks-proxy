/**
 *  \file socks4.cc
 */

#include <glog/logging.h>
#include <socks4.h>

using boost::asio::buffer;
using boost::asio::ip::tcp;
using boost::system::error_code;

using boost::asio::async_connect;
using boost::asio::async_read;
using boost::asio::async_write;
using boost::asio::read;
using boost::asio::write;

void Socks4Handshake(boost::asio::ip::tcp::socket &conn,
                     const boost::asio::ip::tcp::endpoint &addr,
                     const std::string &user) {
    LOG(INFO) << "chaining proxies to " << addr;
    error_code ec;
    uint16_t port = addr.port();
    union {
        uint32_t ipv4;
        uint8_t bytes[4];
    };

    ipv4 = addr.address().to_v4().to_ulong();
    Hello hello = {
        4u,
        1u,
        (uint16_t)(((port & 0xff00) >> 8) | ((port & 0x00ff) << 8)),
        ((uint32_t)bytes[3] << 0) |
            ((uint32_t)bytes[2] << 8) |
            ((uint32_t)bytes[1] << 16) |
            ((uint32_t)bytes[0] << 24),
    };

    write(conn, buffer((void *)&hello, sizeof(hello)), ec);

    if (ec) {
        throw std::runtime_error("failed to write hello header.");
    }

    write(conn, buffer(user.c_str(), user.size() + 1), ec);

    if (ec) {
        throw std::runtime_error("failed to write user name.");
    }

    read(conn, buffer((void *)&hello, sizeof(hello)), ec);

    if (ec) {
        throw std::runtime_error("failed to read hello header.");
    }
}

void ConnectDirectly(boost::asio::ip::tcp::socket &socket,
                     boost::asio::ip::tcp::endpoint destination) {
    socket.connect(destination);
}

void ConnectProxyChain(boost::asio::ip::tcp::socket &socket,
                       const std::vector<ProxyParams> &proxy_chain,
                       boost::asio::ip::tcp::endpoint destination) {
    if (proxy_chain.empty()) {
        ConnectDirectly(socket, destination);
        return;
    }

    for (size_t i = 0; i != proxy_chain.size(); ++i) {
        if (i == 0) {
            socket.connect(proxy_chain[i].endpoint);
        }

        tcp::endpoint next_endpoint;

        if (i + 1 == proxy_chain.size()) {
            next_endpoint = destination;
        } else {
            next_endpoint = proxy_chain[i + 1].endpoint;
        }

        Socks4Handshake(socket, next_endpoint, proxy_chain[i].user);
    }
}

void Session::init(void) noexcept {
    doRecvHello();
}

void Session::doConnect(size_t size) noexcept {
    uint16_t dst_port = ((m_hello.dst_port & 0xff00) >> 8 |
                         (m_hello.dst_port & 0x00ff) << 8);
    uint32_t dst_ip = ((m_hello.dst_ip & 0xff000000) >> 24 |
                       (m_hello.dst_ip & 0x00ff0000) >> 8 |
                       (m_hello.dst_ip & 0x0000ff00) << 8 |
                       (m_hello.dst_ip & 0x000000ff) << 24);

    auto that = shared_from_this();
    auto addr = boost::asio::ip::address_v4(dst_ip);
    tcp::endpoint dest(addr, dst_port);

    LOG(INFO) << "connecting to " << dest;

    m_dst.async_connect(dest,
                        [this, that, dest, size](error_code ec) {
                            if (ec) {
                                LOG(INFO) << "failed to connect to " << dest;
                                // request rejected becasue SOCKS server cannot
                                // connect to identd on the client
                                doSendHello(92u);
                                return;
                            }

                            LOG(INFO) << "connected to " << dest;
                            doSendHello(90u);  // request granted

                            if (size) {
                                doSendToServer(size);
                                doRecvFromServer();
                            } else {
                                doRecvFromClient();
                                doRecvFromServer();
                            }
                        });
}

void Session::doRecvHello(void) noexcept {
    LOG(INFO) << "recieving hello message";
    async_read(m_src, buffer(&m_hello, sizeof(Hello)),
               [this, that = shared_from_this()](error_code ec, size_t) {
                   if (ec) {
                       LOG(ERROR) << "failed to recieve hello.";
                       return;
                   }

                   if (m_hello.version != 0x04) {
                       LOG(ERROR) << "wrong version header";
                       return;
                   }

                   if (m_hello.command != 0x01) {
                       LOG(ERROR) << "wrong SOCKS4 command";
                       return;
                   }

                   doRecvUserID(m_buffer_size);
               });
}

void Session::doRecvUserID(size_t rest_size) noexcept {
    LOG(INFO) << "recieving user id";

    auto that = shared_from_this();
    auto offset = m_buffer_size - rest_size;

    m_src.async_read_some(buffer(m_cli2srv.get() + offset, rest_size),
                          [this, that, rest_size](error_code ec,
                                                  size_t length) {
                              if (ec) {
                                  LOG(ERROR) << "failed to recieve user: ["
                                             << ec.value() << "] "
                                             << ec.message();
                                  return;
                              }

                              auto offset = m_buffer_size - rest_size;
                              auto begin = m_cli2srv.get() + offset;
                              auto end = begin + length;

                              auto pos = findUserID(begin, end);

                              if (pos) {
                                  auto ptr = (const char *)m_cli2srv.get();
                                  auto size = pos - m_cli2srv.get();
                                  auto rest = end - pos;

                                  m_user_id = std::string(ptr, size - 1);

                                  LOG(INFO) << "connected " << m_user_id;
                                  moveMemory(pos, end);
                                  doConnect(rest);
                              } else if (rest_size > 0) {
                                  doRecvUserID(rest_size - length);
                              } else {
                                  LOG(ERROR) << "too long user name";
                              }
                          });
}

void Session::doSendHello(uint8_t command) noexcept {
    LOG(INFO) << "sending hello";

    m_hello.version = 0;
    m_hello.command = command;

    async_write(m_src, buffer(&m_hello, sizeof(Hello)),
                [this, that = shared_from_this()](error_code ec, size_t) {
                    if (ec) {
                        LOG(ERROR) << "sending hello failed: ["
                                   << ec.value() << "] " << ec.message();
                        return;
                    }

                    LOG(INFO) << "sent hello";
                });
}

void Session::doRecvFromClient(void) noexcept {
    LOG(INFO) << "recieving from client";
    setupClientTimeout();
    m_src.async_read_some(buffer(m_cli2srv.get(), m_buffer_size),
                          [this, that = shared_from_this()](error_code ec,
                                                            size_t read) {
                              if (ec) {
                                  LOG(ERROR) << "failed to recv from cli: ["
                                             << ec.value() << "] "
                                             << ec.message();
                                  return;
                              }

                              LOG(INFO) << "recv " << read
                                        << " bytes from client";
                              doSendToServer(read);
                          });
}

void Session::doSendToClient(size_t size) noexcept {
    LOG(INFO) << "sending to client " << size << " bytes";
    setupServerTimeout();
    async_write(m_src, buffer(m_srv2cli.get(), size),
                [this, that = shared_from_this()](error_code ec, size_t) {
                    if (ec) {
                        LOG(ERROR) << "failed to send to client: ["
                                   << ec.value() << "] " << ec.message();
                        return;
                    }

                    doRecvFromServer();
                });
}

void Session::doRecvFromServer(void) noexcept {
    LOG(INFO) << "recieving from server";
    setupServerTimeout();
    m_dst.async_read_some(buffer(m_srv2cli.get(), m_buffer_size),
                          [this, that = shared_from_this()](error_code ec,
                                                            size_t read) {
                              if (ec) {
                                  LOG(ERROR) << "failed to recv from srv: ["
                                             << ec.value() << "] "
                                             << ec.message();
                                  return;
                              }

                              LOG(INFO) << "recv " << read
                                        << " bytes from server";
                              doSendToClient(read);
                          });
}

void Session::doSendToServer(size_t size) noexcept {
    LOG(INFO) << "sending to server " << size << " bytes";
    setupClientTimeout();
    async_write(m_dst, buffer(m_cli2srv.get(), size),
                [this, that = shared_from_this()](error_code ec, size_t) {
                    if (ec) {
                        LOG(ERROR) << "failed to send to server: ["
                                   << ec.value() << "] " << ec.message();
                        return;
                    }

                    doRecvFromClient();
                });
}

void Session::moveMemory(uint8_t *begin, uint8_t *end) noexcept {
    for (auto it = begin; it != end; ++it) {
        size_t diff = it - begin;
        m_cli2srv.get()[diff] = *it;
    }
}

uint8_t *Session::findUserID(uint8_t *begin, uint8_t *end) noexcept {
    for (auto it = begin; it != end; ++it) {
        if (*it == '\0') {
            return it + 1;
        }
    }

    return nullptr;
}

void Session::setupClientTimeout(void) noexcept {
    error_code ec;
    m_cli_timer.expires_from_now(m_timeout, ec);

    if (ec) {
        LOG(ERROR) << "failed to setup client timer: [" << ec.value() << "] "
                   << ec.message();
    }

    m_cli_timer.async_wait([this, that = shared_from_this()](error_code ec) {
        onTimeout(ec, true);
    });
}

void Session::setupServerTimeout(void) noexcept {
    error_code ec;
    m_srv_timer.expires_from_now(m_timeout, ec);

    if (ec) {
        LOG(ERROR) << "failed to setup server timer: [" << ec.value() << "] "
                   << ec.message();
    }

    m_srv_timer.async_wait([this, that = shared_from_this()](error_code ec) {
        onTimeout(ec, false);
    });
}

void Session::onTimeout(error_code ec, bool client) noexcept {
    if (ec == boost::asio::error::operation_aborted) {
        return;
    }

    LOG(INFO) << "triggered deadline timer";

    if (client) {
        m_src.cancel(ec);
    } else {
        m_dst.cancel(ec);
    }

    if (ec) {
        LOG(ERROR) << "canceling failed: [" << ec.value() << "] "
                   << ec.message();
    }
}

void Socks4Proxy::startAccept(void) noexcept {
    m_acceptor.async_accept(
        [this, that = shared_from_this()](error_code ec, tcp::socket socket) {
            if (ec) {
                LOG(ERROR) << "failed to accept connections: ["
                           << ec.value() << "] " << ec.message();
                return;
            }

            LOG(INFO) << "accept incomming connection";
            auto session = std::make_shared<Session>(std::move(socket),
                                                     m_timeout);
            session->init();

            [this, that = shared_from_this()](void) {
                startAccept();
            }();
        });
}

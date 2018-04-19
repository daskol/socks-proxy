/**
 *  \file socks5.cc
 */

#include <socks5.h>
#include <memory>
#include <glog/logging.h>

using boost::asio::buffer;
using boost::asio::mutable_buffer;
using boost::asio::ip::tcp;
using boost::system::error_code;

void Socks5Session::init(void) noexcept {
    LOG(INFO) << "Instantiate socks5 session for incomming connection "
               << m_src.remote_endpoint();

    auto that = shared_from_this();
    auto capacity = 4_kb - m_input_size;

    m_src.async_read_some(
        mutable_buffer(m_input_buffer.get() + m_input_size, capacity),
        [this, that] (const error_code &ec, size_t bytes_transfered) {
            recvSubNegotiation(ec, bytes_transfered);
    });
}

void Socks5Session::recvSubNegotiation(const error_code &ec,
                                       size_t bytes_transfered) noexcept {
    LOG(INFO) << "Recieving " << bytes_transfered
              << " byte(s) during subnegotiation";
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
    auto session = std::make_shared<Socks5Session>(std::move(sock), m_timeout);

    session->init();

    m_acceptor.async_accept(
        [this, that] (const error_code &ec, tcp::socket &&socket) {
            accept(ec, std::move(socket));
    });
}

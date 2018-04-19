/**
 *  \file main.cc
 */

#include <memory>
#include <mutex>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>
#include <glog/logging.h>

#include <acl.h>
#include <socks4.h>
#include <socks5.h>

static std::string g_passwd_filename;
static ACL g_acl;

struct SignalHandler {
    std::mutex m_mutex;
    boost::asio::signal_set m_signal_set;

    SignalHandler(void) = delete;
    SignalHandler(boost::asio::io_context &io_context) noexcept
        : m_signal_set{io_context, SIGHUP} {}

    void await(void) {
        m_signal_set.async_wait([this] (auto &ec, int signal) {
            handle_signals(ec, signal);
            await();
        });
    }

    void handle_signals(const boost::system::error_code &ec, int signal) {
        if (ec) {
            LOG(ERROR) << "Signal waiting failed: [" << ec.value() << "] "
                       << ec.message();
            return;
        }

        LOG(INFO) << "Handle signal " << signal << ": reload passwd file";
        std::lock_guard lock(m_mutex);
        g_acl = std::move(ACL::load(g_passwd_filename));
    }
};

int main(int argc, char* argv[]) {
    google::InitGoogleLogging(argv[0]);

    if (argc != 2) {
        LOG(ERROR) << "No password file.";
        return 1;
    }

    LOG(INFO) << "Loading password file from `" << argv[1] << "`...";

    g_passwd_filename = argv[1];
    g_acl = std::move(ACL::load(g_passwd_filename));

    auto address = boost::asio::ip::address_v4::from_string("127.0.0.1");
    boost::asio::ip::tcp::endpoint endpoint(address, 1080);
    boost::asio::io_context io;
    boost::posix_time::time_duration timeout(0, 0, 1, 0); // one second

    auto proxy = std::make_shared<Socks5Proxy>(io, endpoint, timeout, g_acl);
    proxy->run();

    SignalHandler signals(io);
    signals.await();

    io.run();

    return 0;
}

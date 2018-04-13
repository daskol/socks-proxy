#include <socks4.h>

#include <atomic>
#include <random>
#include <thread>

#include <gtest/gtest.h>
#include <glog/logging.h>

#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>

using boost::system::error_code;

static int dummy = [] {
    FLAGS_logtostderr = 1;
    FLAGS_minloglevel = 0;
    google::InitGoogleLogging("test");
    return 1;
}();

struct EchoConn : public std::enable_shared_from_this<EchoConn> {
    EchoConn(boost::asio::io_service& io_service)
        : socket(io_service) {
        buffer.resize(1024);
    }

    boost::asio::ip::tcp::socket socket;
    std::vector<char> buffer;

    void Start() {
        StartRead();
    }

    void StartRead() {
        auto that = shared_from_this();
        socket.async_read_some(boost::asio::buffer(buffer),
                               [this, that](const error_code& error,
                                            size_t bytes_transferred) {
                                   if (bytes_transferred == 0 || error) {
                                       Disconnect();
                                       return;
                                   }

                                   StartWrite(bytes_transferred);
                               });
    }

    void StartWrite(size_t size) {
        auto that = shared_from_this();
        boost::asio::async_write(socket, boost::asio::buffer(buffer.data(), size),
                                 [this, that](const error_code& error,
                                              size_t /* bytes_transferred */ ) {
                                     if (error) {
                                         Disconnect();
                                         return;
                                     }

                                     StartRead();
                                 });
    }

    void Disconnect() {
        LOG(INFO) << "Echo client "
                  << socket.remote_endpoint()
                  << " disconnected";
    }
};

class EchoServer : public std::enable_shared_from_this<EchoServer> {
public:
    EchoServer(boost::asio::io_service& io_service,
               boost::asio::ip::tcp::endpoint endpoint)
        : acceptor_(io_service, endpoint) {}

    void StartAccept() {
        next_conn = std::make_shared<EchoConn>(acceptor_.get_io_service());

        auto that = shared_from_this();
        acceptor_.async_accept(next_conn->socket, [this, that] (const error_code& ec) {
            if (ec) {
                return;
            }

            LOG(INFO) << "Echo server accepted "
                      << next_conn->socket.remote_endpoint();

            next_conn->Start();
            StartAccept();
       });
    }

private:
    boost::asio::ip::tcp::acceptor acceptor_;

    std::shared_ptr<EchoConn> next_conn;
};

class Socks4Test : public ::testing::Test {
public:
    boost::posix_time::time_duration timeout;

    boost::asio::io_service io_service;
    boost::asio::ip::tcp::endpoint proxy_a_endpoint, proxy_b_endpoint;
    boost::asio::ip::tcp::endpoint closed_endpoint, echo_endpoint;

    std::shared_ptr<EchoServer> echo_server;

    Socks4Test() {
        timeout = boost::posix_time::seconds(1);

        auto localhost = boost::asio::ip::address::from_string("127.0.0.1");
        proxy_a_endpoint = {localhost, 33334};
        proxy_b_endpoint = {localhost, 33335};

        closed_endpoint = {localhost, 44444};
        echo_endpoint = {localhost, 44444};
        echo_server = std::make_shared<EchoServer>(io_service, echo_endpoint);
        echo_server->StartAccept();

        worker = std::thread([&] {
            try {
                io_service.run();
            } catch (const std::exception& e) {
                LOG(ERROR) << "io_service stoped: {}" << e.what();
            }
        });
    }

    ~Socks4Test() {
        io_service.stop();
        worker.join();
    }

    std::thread worker;
};

void Shutdown(boost::asio::ip::tcp::socket& socket) {
    socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send);
    boost::system::error_code ec;
    char received;
    ASSERT_EQ(0u, socket.read_some(boost::asio::buffer(&received, 1), ec));
    if (ec != boost::asio::error::eof) {
        throw boost::system::system_error(ec);
    }
}

void TestEchoConnection(boost::asio::ip::tcp::socket& socket) {
    std::vector<char> sent(1024), received(1024);
    srand(42);
    for (int i = 0; i < 10; ++i) {
        for (char& c : sent) {
            c = rand();
        }

        boost::asio::write(socket, boost::asio::buffer(sent));
        boost::asio::read(socket, boost::asio::buffer(received));

        ASSERT_EQ(sent, received);
    }

    Shutdown(socket);
}

void TestMultiThreadEchoConnection(boost::asio::ip::tcp::socket& socket,
                                   int id,
                                   std::atomic<int>& lastId,
                                   std::atomic<bool>& result) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    char sent, received;
    for (int i = 0; i < 100; ++i) {
        sent = dis(gen);
        boost::asio::write(socket, boost::asio::buffer(&sent, 1));
        boost::asio::read(socket, boost::asio::buffer(&received, 1));
        if (id < lastId.load()) {
            result = true;
        }
        lastId = id;
        ASSERT_EQ(sent, received);
    }
    Shutdown(socket);
}

void TestHandShake(boost::asio::ip::tcp::socket& sock,
                   const std::string& str_address,
                   const std::string& str_user,
                   unsigned short port) {
    unsigned char version, command, port_high_byte, port_low_byte, null_byte;
    boost::asio::ip::address_v4::bytes_type bytes_address;
    std::string user;
    user.resize(str_user.size());

    boost::array<boost::asio::mutable_buffer, 7> bufsRead = {
        {boost::asio::buffer(&version, 1),
         boost::asio::buffer(&command, 1),
         boost::asio::buffer(&port_high_byte, 1),
         boost::asio::buffer(&port_low_byte, 1),
         boost::asio::buffer(bytes_address),
         boost::asio::buffer(&user[0], user.size()),
         boost::asio::buffer(&null_byte, 1)}
    };

    boost::system::error_code ec;
    boost::asio::read(sock, bufsRead, ec);
    ASSERT_FALSE(ec);
    // null byte
    ASSERT_TRUE(null_byte == 0);
    // version
    ASSERT_TRUE(version == 0x04);
    // command
    ASSERT_TRUE(command == 0x01);
    // port
    unsigned short recieved_port = port_high_byte;
    recieved_port = (recieved_port << 8) & 0xff00;
    recieved_port |= port_low_byte;
    ASSERT_EQ(recieved_port, port);

    // address
    boost::asio::ip::address_v4 true_address(bytes_address);
    ASSERT_TRUE(true_address.to_string() == str_address);

    // user
    ASSERT_TRUE(user == str_user);

    unsigned char status = 0x5a;

    boost::array<boost::asio::const_buffer, 5> bufsWrite =
        {
            {boost::asio::buffer(&null_byte, 1),
             boost::asio::buffer(&status, 1),
             boost::asio::buffer(&port_high_byte, 1),
             boost::asio::buffer(&port_low_byte, 1),
             boost::asio::buffer(bytes_address)}};

    boost::asio::write(sock, bufsWrite, ec);
    ASSERT_FALSE(ec);
}

class HandShakeTest : public std::enable_shared_from_this<HandShakeTest>
                    , public ::testing::Test {
public:
    const std::string user = "danlark";
    const std::string address = "127.0.0.1";
    static constexpr unsigned short port = 44445;
    boost::asio::ip::tcp::endpoint endpoint;
    boost::asio::io_service io_service;

    HandShakeTest()
        : endpoint(boost::asio::ip::address::from_string(address), port)
        , acceptor(io_service, endpoint)
        , socket(io_service) {
        StartAccept();
        worker = std::thread([&] {
            try {
                io_service.run();
            } catch (const std::exception& e) {
                LOG(ERROR) << "io_service stoped: {}" << e.what();
            }
        });
    }

    ~HandShakeTest() {
        worker.join();
        io_service.stop();
    }

private:
    void StartAccept() {
        acceptor.async_accept(socket,
                              [this](const boost::system::error_code& ec) {
                                  ASSERT_FALSE(ec);
                                  TestHandShake(socket, address, user, port);
                              });
    }

    std::thread worker;
    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::socket socket;
};

TEST_F(HandShakeTest, TestSocks4Handshake) {
    boost::asio::ip::tcp::socket socket(io_service);
    socket.connect(endpoint);

    Socks4Handshake(socket, endpoint, user);

    socket.close();
}

TEST_F(Socks4Test, ClientNoProxy) {
    boost::asio::ip::tcp::socket socket(io_service);

    ConnectProxyChain(socket, {}, echo_endpoint);

    TestEchoConnection(socket);
}

TEST_F(Socks4Test, SingleProxy) {
    auto proxy_a = std::make_shared<Socks4Proxy>(io_service,
                                                 proxy_a_endpoint,
                                                 timeout);

    proxy_a->startAccept();

    boost::asio::ip::tcp::socket socket(io_service);
    ProxyParams proxy_a_params{proxy_a_endpoint, "root"};
    ConnectProxyChain(socket, {proxy_a_params}, echo_endpoint);

    TestEchoConnection(socket);
}

TEST_F(Socks4Test, LongProxyChain) {
    auto proxy_a = std::make_shared<Socks4Proxy>(io_service,
                                                 proxy_a_endpoint,
                                                 timeout);
    proxy_a->startAccept();

    auto proxy_b = std::make_shared<Socks4Proxy>(io_service,
                                                 proxy_b_endpoint,
                                                 timeout);
    proxy_b->startAccept();

    std::vector<ProxyParams> proxy_chain;
    for (int i = 0; i < 16; ++i) {
        auto endpoint = (i % 2) ? proxy_a_endpoint : proxy_b_endpoint;
        proxy_chain.push_back({endpoint, "user" + std::to_string(i)});
    }

    boost::asio::ip::tcp::socket socket(io_service);
    ConnectProxyChain(socket, proxy_chain, echo_endpoint);

    TestEchoConnection(socket);
}

TEST_F(Socks4Test, TimeoutTest) {
    auto proxy_a = std::make_shared<Socks4Proxy>(io_service,
                                                 proxy_a_endpoint,
                                                 timeout);
    proxy_a->startAccept();

    boost::asio::ip::tcp::socket socket(io_service);
    ProxyParams proxy_a_params{proxy_a_endpoint, "root"};
    ConnectProxyChain(socket, {proxy_a_params}, echo_endpoint);
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    std::vector<char> send(1);
    boost::system::error_code ec;
    boost::asio::write(socket, boost::asio::buffer(send), ec);
    ASSERT_EQ(0u, socket.read_some(boost::asio::buffer(send), ec));
    ASSERT_TRUE(ec);
}


TEST_F(Socks4Test, MultiAcceptTest) {
    auto proxy_a = std::make_shared<Socks4Proxy>(io_service,
                                                 proxy_a_endpoint,
                                                 boost::posix_time::seconds(10));

    proxy_a->startAccept();
    std::vector<std::thread> threads;
    std::atomic<int> lastId{0};
    std::atomic<bool> result{false};

    for (size_t i = 0; i < 4; ++i) {
        threads.emplace_back([&, i] {
            boost::asio::ip::tcp::socket socket(io_service);
            ProxyParams proxy_a_params{proxy_a_endpoint,
                                       "root" + std::to_string(i)};
            ConnectProxyChain(socket, {proxy_a_params}, echo_endpoint);
            TestMultiThreadEchoConnection(socket, i,
                                          std::ref(lastId), std::ref(result));
        });
    }

    for (auto&& thread : threads) {
        thread.join();
    }

    ASSERT_TRUE(result.load());
}

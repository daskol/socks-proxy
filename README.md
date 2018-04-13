# SOCKS4 Proxy Server

*simple socks4-proxy in modern c++*

## Overview

**SOCKS proxy** is simple proxy server which implements well-known
[SOCKS4](https://www.openssh.com/txt/socks4.protocol) protocol. It accept and
multiplexes input and output streams in one thread. It supports half-closed TCP
connections. Also default timeout on connection is one second.

```
    Client           Proxy           Server
      |                |               |
      | 1. Connect ->  |               |
      |                |               |
      |  1. Hello -->  |               |
      |                |               |
      |                | 1. Connect -> |
      |  <-- 1. Hello  |               |
      |                |               |
      |                |               |
      | 2. Data ->     |               |
      |                | 2. Data ->    |
      |                |               |
      |                |               |
      | 2. Fin ->      |               |
      |                | 2. Fin ->     |
      |                |               |
      |                | <- 2. Data    |
      | <- 2. Data     |               |
      |                |               |
      |                | <- 2. Fin     |
      | <- 2. Fin      |               |

```

## Assembly

This implementation depends on Boost.System, Boost.Asio, Google Log and Google
Tests. Make dependencoes are `cmake`, `make` and `git`. Google Test is included
into project dependencies as git submodule. So, to get sources one should clone
repo recursively.

```bash
    git clone --recursive https://github.com/daskol/socks-proxy.git
```

And then one could start building as follows.

```bash
    mkdir -p build/release
    cd build/release
    cmake ../.. -DCMAKE_BUILD_TYPE=Release
    make -j2
```

In order to install target binary to system path one should run following.

```bash
    make install
```

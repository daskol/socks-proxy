/**
 *  \file acl.cc
 */

#include <acl.h>
#include <exception>

bool ACL::find(const std::string &user_pass) const noexcept {
    return m_acl.find(user_pass) != m_acl.end();
}

ACL ACL::load(std::istream &is) {
    ACL acl;

    for (std::string pair; std::getline(is, pair); ) {
        if (!pair.empty()) {
            acl.m_acl.insert(pair);
        }
    }

    return acl;
}

ACL ACL::load(const std::string &filename) {
    std::ifstream fin(filename, std::ios::in);

    if (!fin) {
        throw std::runtime_error("There is no file `" + filename + "`.");
    }

    return load(fin);
}

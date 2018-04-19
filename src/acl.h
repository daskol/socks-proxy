/**
 *  \file acl.h
 */

#pragma once

#include <fstream>
#include <string>
#include <unordered_set>

class ACL {
public:
    ACL(void) = default;
    ACL(const ACL &) = default;
    ACL(ACL &&) = default;

    ACL& operator = (const ACL &) = default;
    ACL& operator = (ACL &&) = default;

    bool find(const std::string &user_pass) const noexcept;

    /**
     *  Load authorization data from text file. User names and passwords are
     *  concatenated with colon(:) and there is one user/pass pair on line.
     */

    static ACL load(std::istream &is);
    static ACL load(const std::string &filename);

private:
    std::unordered_set<std::string> m_acl;
};

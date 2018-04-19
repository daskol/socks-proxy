/**
 *  \file common.h
 */

#pragma once

constexpr size_t operator""_kb(unsigned long long kilobytes) {
    return kilobytes * 1024;  // bytes
}

constexpr size_t operator""_mb(unsigned long long megabytes) {
    return megabytes * 1024 * 1024;  // bytes
}

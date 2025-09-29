#pragma once
#include <string>
#include <vector>

class Base64 {
public:
    static std::string encode(const std::string& input);
    static std::string decode(const std::string& input);
    static std::string urlSafeEncode(const std::string& input);
    static std::string urlSafeDecode(const std::string& input);
};

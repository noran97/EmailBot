#pragma once
#include <string>

class LlamaWrapper {
private:
    std::string modelPath;
    std::string executablePath;

public:
    LlamaWrapper(const std::string& modelPath, const std::string& executablePath = "./llama.cpp/main");
    std::string generateResponse(const std::string& prompt);
};

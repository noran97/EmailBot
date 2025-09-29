#include "llama_wrapper.h"
#include <iostream>
#include <stdexcept>
#include <cstdio>
#include <algorithm>

LlamaWrapper::LlamaWrapper(const std::string& modelPath, const std::string& executablePath)
    : modelPath(modelPath), executablePath(executablePath) {}

std::string LlamaWrapper::generateResponse(const std::string& prompt) {
    try {
        std::string systemPrompt = "You are a helpful email assistant. Write a professional and concise email response.\n\n";
        std::string fullPrompt = systemPrompt + prompt + "\n\nResponse:";

        std::string escapedPrompt = fullPrompt;
        std::replace(escapedPrompt.begin(), escapedPrompt.end(), '"', '\'');

        std::string command = executablePath +
            " -m \"" + modelPath + "\" -p \"" + escapedPrompt +
            "\" -n 256 --temp 0.7 -c 2048 -no-cnv";

        FILE* pipe = popen(command.c_str(), "r");
        if (!pipe) throw std::runtime_error("Failed to run llama.cpp");

        std::string result;
        char buffer[128];
        while (fgets(buffer, sizeof(buffer), pipe)) {
            result += buffer;
        }
        pclose(pipe);

        size_t pos = result.find("Response:");
        if (pos != std::string::npos) result = result.substr(pos + 9);

        result.erase(0, result.find_first_not_of(" \n\r\t"));
        result.erase(result.find_last_not_of(" \n\r\t") + 1);

        if (result.empty()) {
            return "Thank you for your email. I have received your message and will review it.";
        }
        return result;
    } catch (...) {
        return "Thank you for your email. I apologize, but I cannot respond properly right now.";
    }
}

#pragma once

#include "jwt.h"
#include "base64.h"
#include "llama_wrapper.h"

#include <string>
#include <vector>
#include <regex>
#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <filesystem>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <tesseract/baseapi.h>
#include <leptonica/allheaders.h>
#include <opencv2/opencv.hpp>
#include <poppler/cpp/poppler-document.h>
#include <poppler/cpp/poppler-page.h>

using json = nlohmann::json;

// ===== Utility Functions =====
std::string cleanEmailBody(const std::string &rawEmail);

// ===== Structures =====
struct HttpResponse {
    std::string data;
    long response_code;
};

struct Attachment {
    std::string filename;
    std::string mimeType;
    std::string attachmentId;
    std::string data; // base64 encoded
    size_t size;
    std::string extractedText; 
    std::string contentType;
};

struct EmailMessage {
    std::string id;
    std::string threadId;
    std::string sender;
    std::string subject;
    std::string body;
    std::vector<std::string> labels;
    std::vector<Attachment> attachments;
};

// ===== Classes =====
class ImageProcessor {
public:
    ImageProcessor();
    ~ImageProcessor();
    std::string extractTextFromImage(const std::string& imageData, const std::string& mimeType);

private:
    tesseract::TessBaseAPI* tess;
    std::string getImageExtension(const std::string& mimeType);
    std::string processImageFile(const std::string& imagePath);
    cv::Mat preprocessImage(const cv::Mat& image);
    std::string cleanExtractedText(const std::string& text);
};

class PDFExtractor {
public:
    static std::string extractTextFromPDF(const std::string& pdfData);

private:
    static std::string extractWithPoppler(const std::string& pdfPath);
};

#include <iostream>
#include <string>
#include <vector>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <fstream>
#include <sstream>
#include <thread>
#include <chrono>
#include <regex>
#include <cstdlib>
#include <poppler/cpp/poppler-document.h>
#include <poppler/cpp/poppler-page.h>
#include <filesystem>
using json = nlohmann::json;
#include <string>
#include <regex>
#include <sstream>
#include <vector>
#include <algorithm>
#include <tesseract/baseapi.h>
#include <leptonica/allheaders.h>
#include <opencv2/opencv.hpp>
#include "gmail_client.h"
ImageProcessor::ImageProcessor() {
        tess = new tesseract::TessBaseAPI();
        // Initialize tesseract with English language
        if (tess->Init(NULL, "eng")) {
            throw std::runtime_error("Could not initialize tesseract");
        }
        
        // Set page segmentation mode for better accuracy
        tess->SetPageSegMode(tesseract::PSM_AUTO);
    }
    
ImageProcessor::~ImageProcessor() {
        if (tess) {
            tess->End();
            delete tess;
        }
    }
    
std::string ImageProcessor::extractTextFromImage(const std::string& imageData, const std::string& mimeType) {
        try {
            // Save image data to temporary file
            std::string tempFile = "/tmp/temp_img_" + std::to_string(time(nullptr));
            std::string extension = getImageExtension(mimeType);
            tempFile += extension;
            
            std::ofstream file(tempFile, std::ios::binary);
            file.write(imageData.c_str(), imageData.size());
            file.close();
            
            // Process image and extract text
            std::string extractedText = processImageFile(tempFile);
            
            // Clean up temporary file
            std::filesystem::remove(tempFile);
            
            return extractedText;
        } catch (const std::exception& e) {
            std::cerr << "Image processing error: " << e.what() << std::endl;
            return "";
        }
    }
std::string ImageProcessor::getImageExtension(const std::string& mimeType) {
        if (mimeType == "image/jpeg" || mimeType == "image/jpg") return ".jpg";
        if (mimeType == "image/png") return ".png";
        if (mimeType == "image/gif") return ".gif";
        if (mimeType == "image/bmp") return ".bmp";
        if (mimeType == "image/tiff") return ".tiff";
        return ".jpg"; // default
    }
    
std::string ImageProcessor::processImageFile(const std::string& imagePath) {
        try {
            // Load image with OpenCV for preprocessing
            cv::Mat image = cv::imread(imagePath);
            if (image.empty()) {
                std::cerr << "Could not load image: " << imagePath << std::endl;
                return "";
            }
            
            // Preprocess image for better OCR
            cv::Mat processedImage = preprocessImage(image);
            
            // Save processed image temporarily
            std::string processedPath = imagePath + "_processed.png";
            cv::imwrite(processedPath, processedImage);
            
            // Use Tesseract OCR
            Pix* pix = pixRead(processedPath.c_str());
            if (!pix) {
                std::cerr << "Could not read processed image with Leptonica" << std::endl;
                return "";
            }
            
            tess->SetImage(pix);
            char* outText = tess->GetUTF8Text();
            std::string result = outText ? std::string(outText) : "";
            
            // Cleanup
            delete[] outText;
            pixDestroy(&pix);
            std::filesystem::remove(processedPath);
            
            return cleanExtractedText(result);
            
        } catch (const std::exception& e) {
            std::cerr << "OCR processing error: " << e.what() << std::endl;
            return "";
        }
    }
    
cv::Mat ImageProcessor::preprocessImage(const cv::Mat& image) {
        cv::Mat processed;
        
        // Convert to grayscale
        cv::cvtColor(image, processed, cv::COLOR_BGR2GRAY);
        
        // Apply Gaussian blur to reduce noise
        cv::GaussianBlur(processed, processed, cv::Size(3, 3), 0);
        
        // Apply threshold to get binary image
        cv::threshold(processed, processed, 0, 255, cv::THRESH_BINARY + cv::THRESH_OTSU);
        
        // Morphological operations to clean up
        cv::Mat kernel = cv::getStructuringElement(cv::MORPH_RECT, cv::Size(2, 2));
        cv::morphologyEx(processed, processed, cv::MORPH_CLOSE, kernel);
        
        return processed;
    }
    
std::string ImageProcessor::cleanExtractedText(const std::string& text) {
        std::string cleaned = text;
        
        // Remove excessive whitespace
        cleaned = std::regex_replace(cleaned, std::regex("\\s+"), " ");
        
        // Remove special characters that are likely OCR errors
        cleaned = std::regex_replace(cleaned, std::regex("[|\\\\/_~`]"), " ");
        
        // Trim
        cleaned.erase(0, cleaned.find_first_not_of(" \n\r\t"));
        cleaned.erase(cleaned.find_last_not_of(" \n\r\t") + 1);
        
        return cleaned;
    }

 std::string PDFExtractor::extractTextFromPDF(const std::string& pdfData) {
        try {
            // Save PDF data to temporary file
            std::string tempFile = "/tmp/temp_cv_" + std::to_string(time(nullptr)) + ".pdf";
            std::ofstream file(tempFile, std::ios::binary);
            file.write(pdfData.c_str(), pdfData.size());
            file.close();
            
            // Extract text using Poppler
            std::string extractedText = extractWithPoppler(tempFile);
            
            // Clean up temporary file
            std::filesystem::remove(tempFile);
            
            return extractedText;
        } catch (const std::exception& e) {
            std::cerr << "PDF extraction error: " << e.what() << std::endl;
            return "";
        }
    }

 std::string PDFExtractor::extractWithPoppler(const std::string& pdfPath) {
        std::string allText;
        
        try {
            auto doc = poppler::document::load_from_file(pdfPath);
            if (!doc) {
                std::cerr << "Failed to load PDF document" << std::endl;
                return "";
            }
            
            int pages = doc->pages();
            for (int i = 0; i < pages; ++i) {
                auto page = doc->create_page(i);
                if (page) {
                    std::string pageText = page->text().to_latin1();
                    allText += pageText + "\n";
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Poppler extraction error: " << e.what() << std::endl;
            return "";
        }
        
        return allText;
    }

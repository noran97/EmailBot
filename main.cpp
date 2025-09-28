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
#include <algorithm>
#include <tesseract/baseapi.h>
#include <leptonica/allheaders.h>
#include <opencv2/opencv.hpp>

#include "base64.h"
#include "llama_wrapper.h"
#include "gmail_client.h"
// Utility: trim whitespace
static inline std::string trim(const std::string &s) {
    auto start = s.find_first_not_of(" \t\n\r");
    auto end = s.find_last_not_of(" \t\n\r");
    return (start == std::string::npos) ? "" : s.substr(start, end - start + 1);
}

std::string cleanEmailBody(const std::string &rawEmail) {
    std::string text = rawEmail;

    // 1. Remove HTML tags (covers <div ...>, <br/>, etc.)
    text = std::regex_replace(text, std::regex("<[^>]+>"), " ");

    // 2. Decode common HTML entities
    text = std::regex_replace(text, std::regex("&nbsp;"), " ");
    text = std::regex_replace(text, std::regex("&amp;"), "&");
    text = std::regex_replace(text, std::regex("&lt;"), "<");
    text = std::regex_replace(text, std::regex("&gt;"), ">");
    text = std::regex_replace(text, std::regex("&#39;"), "'");
    text = std::regex_replace(text, std::regex("&quot;"), "\"");

    // 3. Collapse multiple spaces/newlines
    text = std::regex_replace(text, std::regex("[ \t]+"), " ");
    text = std::regex_replace(text, std::regex("\n{2,}"), "\n");

    // 4. Trim
    auto start = text.find_first_not_of(" \n\r\t");
    auto end = text.find_last_not_of(" \n\r\t");
    if (start == std::string::npos) return "";
    return text.substr(start, end - start + 1);
}

// Callback function for libcurl
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, HttpResponse* response) {
    size_t total_size = size * nmemb;
    response->data.append(static_cast<char*>(contents), total_size);
    return total_size;
}


class GmailClient {
private:
    std::string accessToken;
    CURL* curl;
    
    HttpResponse makeHttpRequest(const std::string& url, const std::vector<std::string>& headers = {}, 
                                const std::string& postData = "") {
        HttpResponse response;
        response.response_code = 0;
        
        if (!curl) {
            curl = curl_easy_init();
        }
        
        if (!curl) {
            throw std::runtime_error("Failed to initialize CURL");
        }
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L); // Set to 1L for debugging
        
        struct curl_slist* headerList = nullptr;
        for (const auto& header : headers) {
            headerList = curl_slist_append(headerList, header.c_str());
        }
        
        if (headerList) {
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerList);
        }
        
        if (!postData.empty()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, postData.length());
        }
        
        CURLcode res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.response_code);
        
        if (headerList) {
            curl_slist_free_all(headerList);
        }
        
        // Reset curl for next request
        curl_easy_reset(curl);
        
        if (res != CURLE_OK) {
            throw std::runtime_error("CURL request failed: " + std::string(curl_easy_strerror(res)));
        }
        
        return response;
    }
    
    std::string extractTextFromHtml(const std::string& html) {
        // Simple HTML tag removal
        std::regex htmlTags("<[^>]*>");
        std::string text = std::regex_replace(html, htmlTags, " ");
        
        // Replace HTML entities
        text = std::regex_replace(text, std::regex("&nbsp;"), " ");
        text = std::regex_replace(text, std::regex("&lt;"), "<");
        text = std::regex_replace(text, std::regex("&gt;"), ">");
        text = std::regex_replace(text, std::regex("&amp;"), "&");
        text = std::regex_replace(text, std::regex("&quot;"), "\"");
        
        // Clean up whitespace
        text = std::regex_replace(text, std::regex("\\s+"), " ");
        
        return text;
    }

public:
    GmailClient() : curl(nullptr) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }
    
    ~GmailClient() {
        if (curl) {
            curl_easy_cleanup(curl);
        }
        curl_global_cleanup();
    }
EmailMessage getEmailDetails(const std::string& messageId) {
        EmailMessage email;
        
        try {
            std::string url = "https://gmail.googleapis.com/gmail/v1/users/me/messages/" + messageId + "?format=full";
            std::vector<std::string> headers = {"Authorization: Bearer " + accessToken};
            
            HttpResponse response = makeHttpRequest(url, headers);
            
            if (response.response_code != 200) {
                std::cerr << "Failed to fetch message details for ID " << messageId << std::endl;
                return email;
            }
            
            json message = json::parse(response.data);
            
            email.id = messageId;
            if (message.contains("threadId")) {
                email.threadId = message["threadId"];
            }
            
            // Extract headers
            if (message.contains("payload") && message["payload"].contains("headers")) {
                for (const auto& header : message["payload"]["headers"]) {
                    std::string name = header["name"];
                    std::string value = header["value"];
                    
                    if (name == "From") {
                        email.sender = value;
                    } else if (name == "Subject") {
                        email.subject = value;
                    }
                }
            }
            
            // Extract body and attachments
            if (message.contains("payload")) {
                email.body = extractEmailBody(message["payload"]);
                email.attachments = extractAttachments(message["payload"], messageId);
            }
            
            // Extract labels
            if (message.contains("labelIds")) {
                for (const auto& label : message["labelIds"]) {
                    email.labels.push_back(label);
                }
            }
            
        } catch (const std::exception& e) {
            std::cerr << "Error getting email details: " << e.what() << std::endl;
        }
        
        return email;
    }

std::vector<Attachment> extractAttachments(const json& payload, const std::string& messageId) {
        std::vector<Attachment> attachments;
        
        try {
            if (payload.contains("parts")) {
                for (const auto& part : payload["parts"]) {
                    extractAttachmentsFromPart(part, attachments, messageId);
                }
            } else if (payload.contains("body") && payload["body"].contains("attachmentId")) {
                // Single attachment
                Attachment att;
                if (payload.contains("filename")) {
                    att.filename = payload["filename"];
                }
                if (payload.contains("mimeType")) {
                    att.mimeType = payload["mimeType"];
                }
                if (payload["body"].contains("attachmentId")) {
                    att.attachmentId = payload["body"]["attachmentId"];
                    att.data = downloadAttachment(messageId, att.attachmentId);
                    att.contentType = determineContentType(att.mimeType, att.filename);
                }
                attachments.push_back(att);
            }
        } catch (const std::exception& e) {
            std::cerr << "Error extracting attachments: " << e.what() << std::endl;
        }
        
        return attachments;
    }

void extractAttachmentsFromPart(const json& part, std::vector<Attachment>& attachments, const std::string& messageId) {
        try {
            if (part.contains("filename") && !part["filename"].get<std::string>().empty()) {
                Attachment att;
                att.filename = part["filename"];
                
                if (part.contains("mimeType")) {
                    att.mimeType = part["mimeType"];
                }
                
                if (part.contains("body") && part["body"].contains("attachmentId")) {
                    att.attachmentId = part["body"]["attachmentId"];
                    if (part["body"].contains("size")) {
                        att.size = part["body"]["size"];
                    }
                    
                    att.contentType = determineContentType(att.mimeType, att.filename);
                    
                    // Download PDFs and images
                    if (att.contentType == "pdf" || att.contentType == "image") {
                        att.data = downloadAttachment(messageId, att.attachmentId);
                    }
                }
                
                attachments.push_back(att);
            }
            
            // Recursively check nested parts
            if (part.contains("parts")) {
                for (const auto& subPart : part["parts"]) {
                    extractAttachmentsFromPart(subPart, attachments, messageId);
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error extracting part: " << e.what() << std::endl;
        }
    }
    std::string determineContentType(const std::string& mimeType, const std::string& filename) {
        // Check for PDF
        if (mimeType == "application/pdf" || 
            filename.find(".pdf") != std::string::npos) {
            return "pdf";
        }
        
        // Check for images
        if (mimeType.find("image/") == 0 || 
            filename.find(".jpg") != std::string::npos ||
            filename.find(".jpeg") != std::string::npos ||
            filename.find(".png") != std::string::npos ||
            filename.find(".gif") != std::string::npos ||
            filename.find(".bmp") != std::string::npos ||
            filename.find(".tiff") != std::string::npos) {
            return "image";
        }
        
        return "other";
    }
    std::string downloadAttachment(const std::string& messageId, const std::string& attachmentId) {
        try {
            std::string url = "https://gmail.googleapis.com/gmail/v1/users/me/messages/" + 
                             messageId + "/attachments/" + attachmentId;
            std::vector<std::string> headers = {"Authorization: Bearer " + accessToken};
            
            HttpResponse response = makeHttpRequest(url, headers);
            
            if (response.response_code == 200) {
                json attachmentData = json::parse(response.data);
                if (attachmentData.contains("data")) {
                    std::string encodedData = attachmentData["data"];
                    // Convert URL-safe base64 to standard base64
                    std::replace(encodedData.begin(), encodedData.end(), '-', '+');
                    std::replace(encodedData.begin(), encodedData.end(), '_', '/');
                    while (encodedData.length() % 4) {
                        encodedData += "=";
                    }
                    return Base64::decode(encodedData);
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error downloading attachment: " << e.what() << std::endl;
        }
        
        return "";
    }
    bool authenticate(const std::string& credentialsFile) {
        try {
            std::ifstream file(credentialsFile);
            if (!file.is_open()) {
                std::cerr << "Failed to open credentials file: " << credentialsFile << std::endl;
                return false;
            }
            
            json credentials;
            file >> credentials;
            
            // Check if this is a service account or OAuth2 credentials
            if (credentials.contains("type") && credentials["type"] == "service_account") {
                std::cerr << "Service account authentication is not suitable for Gmail API access to personal emails." << std::endl;
                std::cerr << "Please use OAuth2 credentials instead." << std::endl;
                return false;
            } else {
                return authenticateOAuth2(credentials);
            }
        } catch (const std::exception& e) {
            std::cerr << "Authentication error: " << e.what() << std::endl;
            return false;
        }
    }
    
    bool authenticateOAuth2(const json& credentials) {
        try {
            // Check if we have a refresh token saved
            std::ifstream tokenFile("refresh_token.txt");
            std::string refreshToken;
            
            if (tokenFile.is_open()) {
                std::getline(tokenFile, refreshToken);
                tokenFile.close();
                
                if (!refreshToken.empty()) {
                    std::cout << "Using saved refresh token..." << std::endl;
                    return refreshAccessToken(credentials, refreshToken);
                }
            }
            
            // If no refresh token, we need to do the OAuth2 flow
            return performOAuth2Flow(credentials);
            
        } catch (const std::exception& e) {
            std::cerr << "OAuth2 authentication error: " << e.what() << std::endl;
            return false;
        }
    }
    
    bool performOAuth2Flow(const json& credentials) {
        std::string clientId, clientSecret;
        
        // Handle both desktop app and web app credential formats
        if (credentials.contains("installed")) {
            clientId = credentials["installed"]["client_id"];
            clientSecret = credentials["installed"]["client_secret"];
        } else if (credentials.contains("web")) {
            clientId = credentials["web"]["client_id"];
            clientSecret = credentials["web"]["client_secret"];
        } else {
            std::cerr << "Invalid OAuth2 credentials format" << std::endl;
            return false;
        }
        
        // Generate authorization URL
        std::string scope = "https://www.googleapis.com/auth/gmail.modify";
        std::string redirectUri = "urn:ietf:wg:oauth:2.0:oob"; // For desktop apps
        
        std::string authUrl = "https://accounts.google.com/o/oauth2/v2/auth?"
                             "client_id=" + clientId +
                             "&redirect_uri=" + redirectUri +
                             "&scope=" + scope +
                             "&response_type=code" +
                             "&access_type=offline";
        
        std::cout << "\n=== OAuth2 Setup Required ===" << std::endl;
        std::cout << "1. Open this URL in your browser:" << std::endl;
        std::cout << authUrl << std::endl;
        std::cout << "\n2. Complete the authorization" << std::endl;
        std::cout << "3. Copy the authorization code and paste it here: ";
        
        std::string authCode;
        std::getline(std::cin, authCode);
        
        if (authCode.empty()) {
            std::cerr << "No authorization code provided" << std::endl;
            return false;
        }
        
        // Exchange authorization code for tokens
        std::string postData = "code=" + authCode +
                              "&client_id=" + clientId +
                              "&client_secret=" + clientSecret +
                              "&redirect_uri=" + redirectUri +
                              "&grant_type=authorization_code";
        
        HttpResponse response = makeHttpRequest("https://oauth2.googleapis.com/token",
                                              {"Content-Type: application/x-www-form-urlencoded"},
                                              postData);
        
        if (response.response_code == 200) {
            json tokenResponse = json::parse(response.data);
            accessToken = tokenResponse["access_token"];
            
            if (tokenResponse.contains("refresh_token")) {
                std::string refreshToken = tokenResponse["refresh_token"];
                // Save refresh token for future use
                std::ofstream tokenFile("refresh_token.txt");
                tokenFile << refreshToken;
                tokenFile.close();
                std::cout << "Refresh token saved for future use." << std::endl;
            }
            
            std::cout << "OAuth2 authentication successful!" << std::endl;
            return true;
        } else {
            std::cerr << "Token exchange failed (HTTP " << response.response_code << "): " << response.data << std::endl;
            return false;
        }
    }
    
    bool refreshAccessToken(const json& credentials, const std::string& refreshToken) {
        try {
            std::string clientId, clientSecret;
            
            if (credentials.contains("installed")) {
                clientId = credentials["installed"]["client_id"];
                clientSecret = credentials["installed"]["client_secret"];
            } else if (credentials.contains("web")) {
                clientId = credentials["web"]["client_id"];
                clientSecret = credentials["web"]["client_secret"];
            } else {
                std::cerr << "Invalid OAuth2 credentials format" << std::endl;
                return false;
            }
            
            std::string postData = "client_id=" + clientId +
                                  "&client_secret=" + clientSecret +
                                  "&refresh_token=" + refreshToken +
                                  "&grant_type=refresh_token";
            
            HttpResponse response = makeHttpRequest("https://oauth2.googleapis.com/token",
                                                  {"Content-Type: application/x-www-form-urlencoded"},
                                                  postData);
            
            if (response.response_code == 200) {
                json tokenResponse = json::parse(response.data);
                accessToken = tokenResponse["access_token"];
                std::cout << "Access token refreshed successfully" << std::endl;
                return true;
            } else {
                std::cerr << "Token refresh failed (HTTP " << response.response_code << "): " << response.data << std::endl;
                // Delete the invalid refresh token
                std::remove("refresh_token.txt");
                return false;
            }
        } catch (const std::exception& e) {
            std::cerr << "Token refresh error: " << e.what() << std::endl;
            return false;
        }
    }
    
    std::vector<EmailMessage> getUnreadEmails() {
        std::vector<EmailMessage> emails;
        
        try {
            if (accessToken.empty()) {
                std::cerr << "No access token available" << std::endl;
                return emails;
            }
            
            std::string url = "https://gmail.googleapis.com/gmail/v1/users/me/messages?q=is:unread&maxResults=10";
            std::vector<std::string> headers = {"Authorization: Bearer " + accessToken};
            
            std::cout << "Making request to: " << url << std::endl;
            HttpResponse response = makeHttpRequest(url, headers);
            
            std::cout << "Response code: " << response.response_code << std::endl;
            
            if (response.response_code == 401) {
                std::cerr << "Access token expired. Please re-authenticate." << std::endl;
                return emails;
            }
            
            if (response.response_code != 200) {
                std::cerr << "Failed to fetch message list (HTTP " << response.response_code << "): " << response.data << std::endl;
                return emails;
            }
            
            json messageList = json::parse(response.data);
            
            if (messageList.contains("messages")) {
                std::cout << "Found " << messageList["messages"].size() << " unread messages to process" << std::endl;
                for (const auto& msgInfo : messageList["messages"]) {
                    std::string messageId = msgInfo["id"];
                    EmailMessage email = getEmailDetails(messageId);
                    if (!email.id.empty()) {
                        emails.push_back(email);
                    }
                }
            } else {
                std::cout << "No unread messages found" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error getting unread emails: " << e.what() << std::endl;
        }
        
        return emails;
    }
    
 
    
    std::string extractEmailBody(const json& payload) {
        std::string body;
        
        try {
            if (payload.contains("body") && payload["body"].contains("data")) {
                std::string encodedData = payload["body"]["data"];
                // Gmail uses URL-safe base64, so we need to convert it
                std::string standardB64 = encodedData;
                std::replace(standardB64.begin(), standardB64.end(), '-', '+');
                std::replace(standardB64.begin(), standardB64.end(), '_', '/');
                
                // Add padding if needed
                while (standardB64.length() % 4) {
                    standardB64 += "=";
                }
                
                body = Base64::decode(standardB64);
            } else if (payload.contains("parts")) {
                for (const auto& part : payload["parts"]) {
                    std::string partBody = extractEmailBody(part);
                    if (!partBody.empty()) {
                        body += partBody + "\n";
                    }
                }
            }
            
            // If it's HTML, extract text
            if (body.find("<html>") != std::string::npos || body.find("<HTML>") != std::string::npos) {
                body = extractTextFromHtml(body);
            }
            
            // Clean up whitespace
            body = std::regex_replace(body, std::regex("\\s+"), " ");
            // Trim
            body.erase(0, body.find_first_not_of(" \t\n\r"));
            body.erase(body.find_last_not_of(" \t\n\r") + 1);
            
        } catch (const std::exception& e) {
            std::cerr << "Error extracting email body: " << e.what() << std::endl;
        }
        
        return body;
    }
    
    bool sendReply(const std::string& to, const std::string& subject, 
                   const std::string& body, const std::string& threadId = "") {
        try {
            // Create proper email headers and body
            std::stringstream emailStream;
            emailStream << "To: " << to << "\r\n";
            emailStream << "Subject: " << subject << "\r\n";
            emailStream << "Content-Type: text/plain; charset=utf-8\r\n";
            emailStream << "MIME-Version: 1.0\r\n";
            emailStream << "\r\n";
            emailStream << body;
            
            std::string emailContent = emailStream.str();
            
            // Encode as URL-safe base64
            std::string encodedMessage = Base64::urlSafeEncode(emailContent);
            
            json messageJson = {
                {"raw", encodedMessage}
            };
            
            if (!threadId.empty()) {
                messageJson["threadId"] = threadId;
            }
            
            std::string url = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send";
            std::vector<std::string> headers = {
                "Authorization: Bearer " + accessToken,
                "Content-Type: application/json"
            };
            
            HttpResponse response = makeHttpRequest(url, headers, messageJson.dump());
            
            if (response.response_code == 200) {
                std::cout << "Email sent successfully to: " << to << std::endl;
                return true;
            } else {
                std::cerr << "Failed to send email (HTTP " << response.response_code << "): " << response.data << std::endl;
                return false;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error sending email: " << e.what() << std::endl;
            return false;
        }
    }
    bool saveDraft(const std::string& to, const std::string& subject, 
               const std::string& body, const std::string& threadId = "") {
    try {
        // Create proper email headers and body
        std::stringstream emailStream;
        emailStream << "To: " << to << "\r\n";
        emailStream << "Subject: " << subject << "\r\n";
        emailStream << "Content-Type: text/plain; charset=utf-8\r\n";
        emailStream << "MIME-Version: 1.0\r\n";
        emailStream << "\r\n";
        emailStream << body;
        
        std::string emailContent = emailStream.str();
        
        // Encode as URL-safe base64
        std::string encodedMessage = Base64::urlSafeEncode(emailContent);
        
        json draftJson = {
            {"message", {
                {"raw", encodedMessage}
            }}
        };
        
        if (!threadId.empty()) {
            draftJson["message"]["threadId"] = threadId;
        }
        
        std::string url = "https://gmail.googleapis.com/gmail/v1/users/me/drafts";
        std::vector<std::string> headers = {
            "Authorization: Bearer " + accessToken,
            "Content-Type: application/json"
        };
        
        HttpResponse response = makeHttpRequest(url, headers, draftJson.dump());
        
        if (response.response_code == 200) {
            json draftResponse = json::parse(response.data);
            std::string draftId = draftResponse["id"];
            std::cout << "Draft saved successfully to: " << to << " (Draft ID: " << draftId << ")" << std::endl;
            return true;
        } else {
            std::cerr << "Failed to save draft (HTTP " << response.response_code << "): " << response.data << std::endl;
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error saving draft: " << e.what() << std::endl;
        return false;
    }
}
    
    bool markAsRead(const std::string& messageId) {
        try {
            json modifyRequest = {
                {"removeLabelIds", {"UNREAD"}}
            };
            
            std::string url = "https://gmail.googleapis.com/gmail/v1/users/me/messages/" + messageId + "/modify";
            std::vector<std::string> headers = {
                "Authorization: Bearer " + accessToken,
                "Content-Type: application/json"
            };
            
            HttpResponse response = makeHttpRequest(url, headers, modifyRequest.dump());
            
            return response.response_code == 200;
        } catch (const std::exception& e) {
            std::cerr << "Error marking email as read: " << e.what() << std::endl;
            return false;
        }
    }
};

class EmailProcessor {
private:
    GmailClient gmail;
    LlamaWrapper llama;
    std::string credentialsFile;
    std::unique_ptr<ImageProcessor> imageProcessor; 
    std::unique_ptr<PDFExtractor> pdfExtractor;

public:
    EmailProcessor(const std::string& modelPath, const std::string& credentialsFile,
                   const std::string& llamaExecutable = "./llama.cpp/main") 
        : llama(modelPath, llamaExecutable), credentialsFile(credentialsFile) {
        try {
            imageProcessor = std::make_unique<ImageProcessor>();
            std::cout << "Image OCR processor initialized successfully" << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Warning: Could not initialize image processor: " << e.what() << std::endl;
        }
        }
    
    bool initialize() {
        std::cout << "Initializing Gmail client..." << std::endl;
        return gmail.authenticate(credentialsFile);
    }
    void processEmails() {
        std::cout << "Checking for new emails..." << std::endl;
        
        std::vector<EmailMessage> emails = gmail.getUnreadEmails();
        
        if (emails.empty()) {
            std::cout << "No unread emails found." << std::endl;
            return;
        }
        
        std::cout << "Found " << emails.size() << " unread emails to process." << std::endl;
        
        for ( auto& email : emails) {
            std::cout << "\n=== Processing Email ===" << std::endl;
            std::cout << "ID: " << email.id << std::endl;
            std::cout << "From: " << email.sender << std::endl;
            std::cout << "Subject: " << email.subject << std::endl;
            std::cout << "Attachments: " << email.attachments.size() << std::endl;
            
            if (email.body.empty()) {
                std::cout << "Email body is empty, skipping..." << std::endl;
                continue;
            }
            
            std::string cleanBody = cleanEmailBody(email.body);
            std::string attachmentText = "";
            
            for (size_t i = 0; i < email.attachments.size(); ++i) {
    auto& attachment = email.attachments[i];
                if (attachment.contentType == "pdf") {
                    std::cout << "Processing PDF: " << attachment.filename << std::endl;
                    if (!attachment.data.empty()) {
                        attachment.extractedText =( PDFExtractor::extractTextFromPDF(attachment.data));
                        if (!attachment.extractedText.empty()) {
                            attachmentText += "\n\n=== PDF Content (" + attachment.filename + ") ===\n" 
                                           + attachment.extractedText;
                            std::cout << "Extracted " << attachment.extractedText.length() 
                                     << " characters from PDF" << std::endl;
                        }
                    }
                } 
                else if (attachment.contentType == "image" && imageProcessor) {
                    std::cout << "Processing image: " << attachment.filename << std::endl;
                    if (!attachment.data.empty()) {
                        attachment.extractedText = imageProcessor->extractTextFromImage(
                            attachment.data, attachment.mimeType);
                        if (!attachment.extractedText.empty()) {
                            attachmentText += "\n\n=== Image Content (" + attachment.filename + ") ===\n" 
                                           + attachment.extractedText;
                            std::cout << "Extracted " << attachment.extractedText.length() 
                                     << " characters from image" << std::endl;
                        }
                    }
                }
            }
            std::string prompt = createEnhancedPrompt(email, cleanBody, attachmentText);
            
            std::cout << "Generating response with llama..." << std::endl;
            std::string response = llama.generateResponse(prompt);
          
            std::cout << "Generated response preview: " << response.substr(0, 100) << "..." << std::endl;
            
            // Extract sender email address (remove name if present)
            std::string senderEmail = email.sender;
            std::regex emailRegex("<([^>]+)>");
            std::smatch match;
            if (std::regex_search(senderEmail, match, emailRegex)) {
                senderEmail = match[1].str();
            } else {
                // If no angle brackets, check if it's just an email
                std::regex pureEmailRegex("([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})");
                if (std::regex_search(senderEmail, match, pureEmailRegex)) {
                    senderEmail = match[1].str();
                }
            }
            
            std::cout << "Sending reply to: " << senderEmail << std::endl;
            
            // Send reply
            std::string replySubject = email.subject;
            if (replySubject.substr(0, 3) != "Re:") {
                replySubject = "Re: " + replySubject;
            }
            
            //bool sent = gmail.sendReply(senderEmail, replySubject, response, email.threadId);
              bool sent = gmail.saveDraft(senderEmail, replySubject, response, email.threadId);
            if (sent) {
                // Mark original email as read
                bool marked = gmail.markAsRead(email.id);
                if (marked) {
                    std::cout << "✓ Successfully processed and replied to email." << std::endl;
                } else {
                    std::cout << "✓ Email sent, but failed to mark as read." << std::endl;
                }
            } else {
                std::cerr << "✗ Failed to send reply." << std::endl;
            }
            
            // Add a small delay between processing emails
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        }
    

    
    void run(int checkIntervalSeconds = 60) {
        std::cout << "Email bot started. Checking every " << checkIntervalSeconds << " seconds." << std::endl;
        std::cout << "Press Ctrl+C to stop." << std::endl;
        
        while (true) {
            try {
                processEmails();
            } catch (const std::exception& e) {
                std::cerr << "Error processing emails: " << e.what() << std::endl;
            }
            
            std::this_thread::sleep_for(std::chrono::seconds(checkIntervalSeconds));
        }
    }
    private:
    std::string createEnhancedPrompt(const EmailMessage& email, 
                                   const std::string& cleanBody, 
                                   const std::string& attachmentText) {
        std::string prompt = "Please write a professional email response to this message.";
        
        if (!attachmentText.empty()) {
            prompt += " The sender has included attachments with additional information.";
        }
        
        prompt += "\n\nFrom: " + email.sender + 
                  "\nSubject: " + email.subject + 
                  "\n\nMessage:\n" + cleanBody;
        
        if (!attachmentText.empty()) {
            prompt += "\n\nAttached Documents Content:" + attachmentText;
        }
        
        return prompt;
    }
};


int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <model_path> <oauth2_credentials_json> [llama_executable_path]" << std::endl;
        std::cerr << "Example: " << argv[0] << " ./model.gguf ./client_secret.json ./llama.cpp/main" << std::endl;
        std::cerr << "\nNote: Use OAuth2 credentials (client_secret.json), not service account credentials." << std::endl;
        return 1;
    }
    
    std::string modelPath = argv[1];
    std::string credentialsFile = argv[2];
    std::string llamaExecutable = (argc > 3) ? argv[3] : "./llama.cpp/main";
    
    std::cout << "Gmail LLaMA Bot Starting..." << std::endl;
    std::cout << "Model: " << modelPath << std::endl;
    std::cout << "Credentials: " << credentialsFile << std::endl;
    std::cout << "LLaMA executable: " << llamaExecutable << std::endl;
    
    try {
        EmailProcessor processor(modelPath, credentialsFile, llamaExecutable);
        
        if (!processor.initialize()) {
            std::cerr << "Failed to initialize email processor." << std::endl;
            return 1;
        }
        
        // Run the email processing loop
        processor.run(60); // Check every 60 seconds
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

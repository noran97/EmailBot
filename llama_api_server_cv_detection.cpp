
#include "httplib.h"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <memory>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <array>
#include <cstdio>

// For PDF to image conversion
#include <poppler/cpp/poppler-document.h>
#include <poppler/cpp/poppler-page.h>
#include <poppler/cpp/poppler-page-renderer.h>
#include <poppler/cpp/poppler-image.h>

using json = nlohmann::json;

// Execute command and capture output
std::string exec_command(const std::string& cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    
    return result;
}

// Convert PDF first page to PNG image
std::string pdf_to_image(const std::string& pdf_path, const std::string& output_dir) {
    std::unique_ptr<poppler::document> doc(poppler::document::load_from_file(pdf_path));
    
    if (!doc || doc->is_locked()) {
        throw std::runtime_error("Cannot open or read PDF: " + pdf_path);
    }
    
    // Get first page only
    std::unique_ptr<poppler::page> page(doc->create_page(0));
    if (!page) {
        throw std::runtime_error("Cannot read first page of PDF");
    }
    
    // Render page to image at 150 DPI
    poppler::page_renderer renderer;
    renderer.set_render_hint(poppler::page_renderer::text_antialiasing);
    renderer.set_render_hint(poppler::page_renderer::antialiasing);
    
    poppler::image img = renderer.render_page(page.get(), 150, 150);
    
    if (!img.is_valid()) {
        throw std::runtime_error("Failed to render PDF page to image");
    }
    
    // Generate output filename
    std::string base_name = pdf_path.substr(pdf_path.find_last_of("/\\") + 1);
    base_name = base_name.substr(0, base_name.find_last_of('.'));
    std::string output_path = output_dir + "/" + base_name + "_page1.png";
    
    // Save as PNG
    if (!img.save(output_path, "png")) {
        throw std::runtime_error("Failed to save image: " + output_path);
    }
    
    std::cout << "Converted PDF to image: " << output_path << std::endl;
    return output_path;
}

// Check if file is a PDF
bool is_pdf_file(const std::string& filename) {
    if (filename.length() < 4) return false;
    std::string ext = filename.substr(filename.length() - 4);
    for (auto& c : ext) c = std::tolower(c);
    return ext == ".pdf";
}

// Create prompt for CV detection with vision
std::string create_cv_detection_prompt() {
    std::string prompt = 
        "You are an AI assistant that extracts information from CV/resume images.\\n\\n"
        "Please analyze the CV image and extract the following information:\\n"
        "1. Name (full name of the candidate)\\n"
        "2. Position (job title or desired position)\\n"
        "3. Skills (list up to 10 key technical skills)\\n"
        "4. Experience (total years of professional experience)\\n"
        "5. Education (highest degree)\\n\\n"
        "Return ONLY valid JSON in this exact format with no additional text:\\n"
        "{\\n"
        "  \\\"name\\\": \\\"Full Name\\\",\\n"
        "  \\\"position\\\": \\\"Job Title\\\",\\n"
        "  \\\"skills\\\": [\\\"skill1\\\", \\\"skill2\\\", \\\"skill3\\\"],\\n"
        "  \\\"experience\\\": \\\"X years\\\",\\n"
        "  \\\"education\\\": \\\"Degree Name\\\"\\n"
        "}\\n\\n"
        "Output:";
    
    return prompt;
}

// Call llama-mtmd-cli to process image
std::string process_cv_with_vision(const std::string& image_path, const std::string& llama_cli_path, const std::string& model_name) {
    std::string prompt = create_cv_detection_prompt();
    
    
    std::string cmd = llama_cli_path + " " +"--hf-token  "+
                      "-hf " + model_name + " "
                      "--image " + image_path + " "
                      "-p \"" + prompt + "\" "
                      "--temp 0.3 "
                      "-n 800 "
                      "2>&1";  // Capture stderr too
    
    std::cout << "Executing vision model..." << std::endl;
    std::cout << "Command: " << cmd << std::endl;
    
    try {
        std::string output = exec_command(cmd);
        std::cout << "Vision model raw output: " << output << std::endl;
        return output;
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to execute vision model: " + std::string(e.what()));
    }
}


json parse_cv_metadata(const std::string& model_output) {
    // 1. Look for the Markdown JSON start and end delimiters for better reliability
    size_t start_marker = model_output.find("```json");
    if (start_marker == std::string::npos) {
        // Fallback: search for first brace if the markdown marker is missing
        start_marker = model_output.find('{');
    } else {
        // Skip the "```json" part
        start_marker += 7; // Length of "```json"
        
        // Skip any newlines or spaces after the marker
        while (start_marker < model_output.length() && (model_output[start_marker] == '\n' || model_output[start_marker] == '\r' || model_output[start_marker] == ' ')) {
            start_marker++;
        }
    }

    size_t end_marker = model_output.rfind('}');
    
    // Check if both markers were found
    if (start_marker != std::string::npos && end_marker != std::string::npos && end_marker > start_marker) {
        // Extract the potential JSON string
        std::string json_str = model_output.substr(start_marker, end_marker - start_marker + 1);

        // Optional: Remove any trailing backticks if the model added them right after '}'
        while (!json_str.empty() && (json_str.back() == '`' || json_str.back() == '\n' || json_str.back() == '\r' || json_str.back() == ' ')) {
             json_str.pop_back();
        }

        try {
            // Attempt to parse the cleaned string
            return json::parse(json_str);
        } catch (const json::parse_error& e) {
            std::cerr << "JSON parse error (Cleaned string failed): " << e.what() << std::endl;
            std::cerr << "Attempted to parse: " << json_str << std::endl;
        }
    } else {
        std::cerr << "JSON delimiters not found or invalid range in model output." << std::endl;
    }
    
    // Return 'Unknown' metadata structure upon failure
    return json{
        {"name", "Unknown"},
        {"position", "Unknown"},
        {"skills", json::array()},
        {"experience", "Unknown"},
        {"education", "Unknown"}
    };
}

int main(int argc, char** argv) {
    try {
        // Configuration - can be overridden by command line args
        std::string model_name = "google/gemma-3-4b-it-qat-q4_0-gguf";
        std::string llama_cli_path = "../externals/llama.cpp/build/bin/llama-mtmd-cli";
        
        // Parse command line arguments
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "--model" && i + 1 < argc) {
                model_name = argv[++i];
            } else if (arg == "--cli-path" && i + 1 < argc) {
                llama_cli_path = argv[++i];
            }
        }
        
        // Check if CLI exists
        struct stat cli_stat;
        if (stat(llama_cli_path.c_str(), &cli_stat) != 0) {
            std::cerr << "ERROR: llama-mtmd-cli not found at: " << llama_cli_path << std::endl;
            std::cerr << "Please build it first or specify correct path with --cli-path" << std::endl;
            return 1;
        }
        
        std::cout << "Configuration:" << std::endl;
        std::cout << "  Model: " << model_name << std::endl;
        std::cout << "  CLI Path: " << llama_cli_path << std::endl;
        
        httplib::Server svr;
        
        // Set max payload size to handle PDF uploads (10MB)
        svr.set_payload_max_length(10 * 1024 * 1024);
        
        svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("{\"status\":\"ok\"}", "application/json");
        });
        
        svr.Post("/ai/inbox/detect-cv", [&model_name, &llama_cli_path](const httplib::Request& req, httplib::Response& res) {
            try {
                // Parse input JSON
                json input_json = json::parse(req.body);
                
                // Validate required fields
                if (!input_json.contains("user_id") || !input_json.contains("email_id") || 
                    !input_json.contains("attachments")) {
                    res.status = 400;
                    res.set_content("{\"error\":\"Missing required fields: user_id, email_id, attachments\"}", 
                                  "application/json");
                    return;
                }
                
                std::string email_id = input_json["email_id"];
                json attachments = input_json["attachments"];
                
                std::cout << "Processing CV detection for email_id: " << email_id << std::endl;
                
                bool cv_detected = false;
                json metadata;
                
                // Check each attachment
                for (const auto& attachment : attachments) {
                    std::string filename = attachment.get<std::string>();
                    std::cout << "Checking attachment: " << filename << std::endl;
                    
                    if (is_pdf_file(filename)) {
                        try {
                            // Convert PDF to image
                            std::string pdf_path = "../uploads/" + filename;
                            std::string temp_dir = "../uploads/temp";
                            
                            // Create temp directory if it doesn't exist
                            struct stat st = {0};
                            if (stat(temp_dir.c_str(), &st) == -1) {
                                if (mkdir(temp_dir.c_str(), 0755) != 0) {
                                    throw std::runtime_error("Failed to create temp directory");
                                }
                            }
                            
                            std::string image_path = pdf_to_image(pdf_path, temp_dir);
                            
                            // Process with vision model via CLI
                            std::string model_output = process_cv_with_vision(image_path, llama_cli_path, model_name);
                            
                            // Parse metadata
                            metadata = parse_cv_metadata(model_output);
                            cv_detected = true;
                            
                            // Clean up temporary image
                            remove(image_path.c_str());
                            
                            // If we found a CV, no need to check other attachments
                            break;
                            
                        } catch (const std::exception& e) {
                            std::cerr << "Error processing PDF " << filename << ": " << e.what() << std::endl;
                            continue;
                        }
                    }
                }
                
                // Create output JSON
                json output_json = {
                    {"email_id", email_id},
                    {"cv_detected", cv_detected}
                };
                
                if (cv_detected) {
                    output_json["metadata"] = metadata;
                } else {
                    output_json["metadata"] = json::object();
                }
                
                res.set_content(output_json.dump(2), "application/json");
                
            } catch (const json::parse_error& e) {
                res.status = 400;
                res.set_content("{\"error\":\"Invalid JSON: " + std::string(e.what()) + "\"}", 
                              "application/json");
            } catch (const std::exception& e) {
                res.status = 500;
                res.set_content("{\"error\":\"" + std::string(e.what()) + "\"}", 
                              "application/json");
            }
        });
        
        std::cout << "\nCV Detection Server (Vision CLI) starting on port 8080..." << std::endl;
        std::cout << "Endpoint: POST /ai/inbox/detect-cv" << std::endl;
        std::cout << "\nMake sure llama-mtmd-cli is built and available at: " << llama_cli_path << std::endl;
        svr.listen("0.0.0.0", 8080);
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

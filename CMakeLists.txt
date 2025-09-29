cmake_minimum_required(VERSION 3.12)
project(GmailLlamaBot)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(OpenCV REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(POPPLER_CPP REQUIRED poppler-cpp)
pkg_check_modules(TESSERACT REQUIRED tesseract)
pkg_check_modules(LEPTONICA REQUIRED lept)


# Find libcurl
pkg_check_modules(CURL REQUIRED libcurl)

# Find nlohmann_json
find_package(nlohmann_json 3.2.0 REQUIRED)

# Add executable
add_executable(gmail_llama_bot main.cpp jwt.cpp base64.cpp llama_wrapper.cpp Image.cpp)

# Link libraries
target_link_libraries(gmail_llama_bot 
    ${CURL_LIBRARIES} 
    OpenSSL::SSL 
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    ${POPPLER_CPP_LIBRARIES}
    ${OpenCV_LIBS} 
    ${TESSERACT_LIBRARIES} 
    ${LEPTONICA_LIBRARIES}
    ${POPPLER_CPP_LIBRARIES}
)

# Include directories
target_include_directories(gmail_llama_bot PRIVATE ${CURL_INCLUDE_DIRS} ${POPPLER_CPP_INCLUDE_DIRS})

# Compiler flags
target_compile_options(gmail_llama_bot PRIVATE ${CURL_CFLAGS_OTHER})

# Set output directory
set_target_properties(gmail_llama_bot PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)


#include <iostream>
#include <curl/curl.h>

// Callback function to capture response data
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userData) {
    userData->append((char*)contents, size * nmemb);
    return size * nmemb;
}

int main() {
    CURL* curl;
    CURLcode res;
    std::string responseString;

    // Initialize libcurl
    curl = curl_easy_init();
    if (curl) {
        // Set URL for the request
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com");

        // Set callback to handle data
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseString);

        // Perform the request
        res = curl_easy_perform(curl);

        // Check for errors
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        } else {
            // Print the full response
            std::cout << "Full response:\n" << responseString << std::endl;
            // Print response length
            std::cout << "Response length: " << responseString.length() << " characters" << std::endl;
        }

        // Cleanup
        curl_easy_cleanup(curl);
    } else {
        std::cerr << "Failed to initialize libcurl" << std::endl;
    }

    return 0;
}

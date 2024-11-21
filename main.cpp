#include <iostream>
#include <string>
#include <curl/curl.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <vector>
#include <libxml/HTMLparser.h>
#include <libxml/xpath.h>
#include <sstream>
#include <iomanip>
#include <thread>
#include <future>
#include <mutex>
using namespace std;


mutex curl_mutex;

// AES Encryption Function (unchanged)
string aes_encrypt(const string& plaintext, const string& key, const string& iv) {
    AES_KEY encrypt_key;
    vector<unsigned char> encrypted(plaintext.size() + AES_BLOCK_SIZE);
    vector<unsigned char> buffer(AES_BLOCK_SIZE);

    AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(key.c_str()), 128, &encrypt_key);

    int num = 0;
    AES_cfb128_encrypt(reinterpret_cast<const unsigned char*>(plaintext.c_str()), encrypted.data(),
                       plaintext.size(), &encrypt_key,
                       reinterpret_cast<unsigned char*>(const_cast<char*>(iv.c_str())),
                       &num, AES_ENCRYPT);

    return string(encrypted.begin(), encrypted.end());
}

// Callback function for libcurl to write the response
size_t write_callback(void* contents, size_t size, size_t nmemb, string* data) {
    data->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Initialize CURL for connection pooling
CURL* init_curl() {
    CURL* curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");  // Enable cookies
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);  // Follow redirects
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);  // Callback for writing data
    }
    return curl;
}

// Thread-safe POST request using the same CURL handle
string send_post_request(CURL* curl, const string& url, const string& post_fields) {
    string response;
    lock_guard<mutex> lock(curl_mutex);  // Ensure only one thread accesses the curl handle at a time
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << endl;
    }
    return response;
}

// Function to extract VIEWSTATE or EVENTVALIDATION from the HTML
string extract_value(const string& html, const string& name) {
    size_t start = html.find(name) + name.length() + 8;  // Adjust position to get value
    size_t end = html.find("\"", start);
    return html.substr(start, end - start);
}

// Parse and print attendance data (unchanged)
void parse_attendance(const string& html) {
    htmlDocPtr doc = htmlReadMemory(html.c_str(), html.size(), NULL, NULL, HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING);
    if (doc == NULL) {
        cerr << "Failed to parse document\n";
        return;
    }

    xmlXPathContextPtr xpathCtx = xmlXPathNewContext(doc);
    xmlXPathObjectPtr xpathObj = xmlXPathEvalExpression(BAD_CAST "//table[@id='tblReport']//tr", xpathCtx);
    
    if (xpathObj == NULL) {
        cerr << "XPath evaluation failed\n";
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return;
    }

    xmlNodeSetPtr nodes = xpathObj->nodesetval;
    for (int i = 0; i < nodes->nodeNr; ++i) {
        xmlNodePtr row = nodes->nodeTab[i];
        for (xmlNodePtr cell = row->children; cell; cell = cell->next) {
            if (cell->type == XML_ELEMENT_NODE) {
                string cell_content = (char*)xmlNodeGetContent(cell);
                cout << cell_content << "\t";
            }
        }
        cout << endl;
    }

    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    xmlFreeDoc(doc);
}

// Worker function for each thread
void handle_request(CURL* curl, const string& student_id, const string& password) {
    // Step 1: Send GET request to login page to fetch VIEWSTATE and EVENTVALIDATION
    string login_url = "https://webprosindia.com/vignanit/default.aspx";
    string login_page = send_post_request(curl, login_url, "");

    string viewstate = extract_value(login_page, "__VIEWSTATE");
    string eventvalidation = extract_value(login_page, "__EVENTVALIDATION");

    // Step 2: Encrypt the password
    string key = "8701661282118308";
    string iv = "8701661282118308";
    string encrypted_password = aes_encrypt(password, key, iv);

    // Step 3: Send POST request with login data
    ostringstream post_data;
    post_data << "__VIEWSTATE=" << viewstate
              << "&__EVENTVALIDATION=" << eventvalidation
              << "&txtId2=" << student_id
              << "&txtPwd2=" << password
              << "&hdnpwd2=" << encrypted_password;

    string post_fields = post_data.str();
    send_post_request(curl, login_url, post_fields);

    // Step 4: Fetch attendance data
    string attendance_url = "https://webprosindia.com/vignanit/Academics/studentacadamicregister.aspx?scrid=2";
    string attendance_data = send_post_request(curl, attendance_url, "");

    // Step 5: Parse attendance data
    parse_attendance(attendance_data);
}

int main() {
    // Initialize CURL with connection pooling
    CURL* curl = init_curl();

    // Number of threads to handle 20-40 requests per second
    const int num_threads = 20;
    vector<thread> threads;

    // Credentials for the students
    string student_ids[] = {"ID_1", "ID_2", "ID_3"};  // Sample student IDs
    string password = "YOUR_PASSWORD";  // Use same password for testing

    // Launch threads to process requests concurrently
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(handle_request, curl, student_ids[i % 3], password);
    }

    // Wait for all threads to complete
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    // Clean up CURL
    curl_easy_cleanup(curl);
    return 0;
}

#include <iostream>
#include <string>
#include <curl/curl.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <iomanip>
#include <sstream>
#include <vector>
#include <nlohmann/json.hpp>
#include <regex>


using json = nlohmann::json;

// Helper function to write response data
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userData) {
    userData->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Helper function to Base64 encode
std::string Base64Encode(const unsigned char* buffer, size_t length) {
    BIO* bio = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    bio = BIO_push(bio, bmem);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::string encoded(bptr->data, bptr->length);
    BIO_free_all(bio);
    return encoded;
}

// AES encryption
std::string EncryptPassword(const std::string& plaintext, const std::string& key, const std::string& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char encrypted[128];
    int len = 0, ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, (unsigned char*)key.c_str(), (unsigned char*)iv.c_str());
    EVP_EncryptUpdate(ctx, encrypted, &len, (unsigned char*)plaintext.c_str(), plaintext.length());
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, encrypted + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return Base64Encode(encrypted, ciphertext_len);
}

// Function to extract a value for a given hidden input name
std::string ExtractValue(const std::string& html, const std::string& fieldName) {
    std::regex pattern("<input[^>]*name=\"" + fieldName + "\"[^>]*value=\"([^\"]*)\"");
    std::smatch match;
    if (std::regex_search(html, match, pattern)) {
        return match[1].str(); // Return the captured group
    }
    return "";
}

std::string FetchAttendance(const std::string& studentId, const std::string& password) {
    std::string loginUrl = "https://webprosindia.com/vignanit/default.aspx";
    std::string responseString;
    CURL* curl = curl_easy_init();
    CURLcode res;

    if (!curl) {
        return "{\"error\": \"Failed to initialize libcurl\"}";
    }

    // Step 1: Fetch login page
    curl_easy_setopt(curl, CURLOPT_URL, loginUrl.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseString);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        return "{\"error\": \"Failed to fetch login page\"}";
    }

    //std::cout << "Step 1 Response:\n" << responseString << "\n\n";

    std::string viewstate = ExtractValue(responseString, "__VIEWSTATE");
    std::string viewstateGenerator = ExtractValue(responseString, "__VIEWSTATEGENERATOR");
    std::string eventValidation = ExtractValue(responseString, "__EVENTVALIDATION");

    std::cout<<"viewstate "<<viewstate<<"\n";
    std::cout<<"viewstateGenerator "<<viewstateGenerator<<"\n";
    std::cout<<"eventValidation "<<eventValidation<<"\n";


    // Encrypt the password
    std::string key = "8701661282118308";
    std::string iv = "8701661282118308";
    std::string encryptedPassword = EncryptPassword(password, key, iv);

    std::cout<<"encryptedPassword "<<encryptedPassword<<"\n";

    // Step 2: Perform login
    std::string postData = "__VIEWSTATE=" + viewstate + 
                           "&__VIEWSTATEGENERATOR=" + viewstateGenerator +
                           "&__EVENTVALIDATION=" + eventValidation +
                           "&txtId2=" + studentId +
                           "&txtPwd2=" + password +
                           "&imgBtn2.x=0&imgBtn2.y=0&hdnpwd2=" + encryptedPassword;

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
    responseString.clear();

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        return "{\"error\": \"Failed to login\"}";
    }

    //std::cout << "Step 2 Response:\n" << responseString << "\n\n";

    // Step 3: Fetch attendance
    std::string attendanceUrl = "https://webprosindia.com/vignanit/Academics/studentacadamicregister.aspx?scrid=2";
    responseString.clear();

    curl_easy_setopt(curl, CURLOPT_URL, attendanceUrl.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        return "{\"error\": \"Failed to fetch attendance data\"}";
    }

   // std::cout << "Step 3 Response:\n" << responseString << "\n\n";

    // Parse attendance table using regex or an HTML parser
    // Extract the relevant data and format it as JSON

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    return "{\"status\": \"Attendance data fetched successfully\"}";
}


int main() {
    std::string studentId = "22l31a0596";
    std::string password = "Gan@2004";

    std::string result = FetchAttendance(studentId, password);
    std::cout << result << std::endl;

    return 0;
}

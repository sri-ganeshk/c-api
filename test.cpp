#include <iostream>
#include <string>
#include "civetweb.h"

// Callback function for handling POST requests
int post_callback(struct mg_connection* conn, void* cbdata) {
    char post_data[1024];
    int post_data_len = mg_read(conn, post_data, sizeof(post_data));

    std::string data(post_data, post_data_len);
    std::string user_id, password;

    // Extract user_id and password from POST data (for simplicity, assuming data is URL encoded)
    size_t id_pos = data.find("user_id=");
    size_t pass_pos = data.find("&password=");

    if (id_pos != std::string::npos && pass_pos != std::string::npos) {
        user_id = data.substr(id_pos + 8, pass_pos - (id_pos + 8));
        password = data.substr(pass_pos + 10);
    }

    std::cout << "User ID: " << user_id << "\n";
    std::cout << "Password: " << password << "\n";

    // Send a response
    mg_printf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n");
    mg_printf(conn, "Received user ID: %s and password: %s", user_id.c_str(), password.c_str());

    return 200; // HTTP OK
}

int main() {
    const char* options[] = {
        "listening_ports", "8080",  // The port to listen on
        0
    };

    // Initialize the CivetWeb server
    struct mg_context* ctx = mg_start(NULL, 0, options);

    // Set up the handler for POST requests
    mg_set_request_handler(ctx, "/login", post_callback, 0);

    std::cout << "Server is running on http://localhost:8080...\n";

    // Keep the server running until interrupted
    getchar();

    // Stop the server
    mg_stop(ctx);

    return 0;
}

// network_service.cpp
// Purposefully insecure C++ service for training.
// Issues: unsanitized input echo, hardcoded token, insecure logging, header injection.

#include <iostream>
#include <string>
#include <fstream>
#include <sstream>

using namespace std;

const string SECRET_TOKEN = "hardcoded-token-9999";  // hardcoded secret

string handle_request(const string &req) {
    // parse a very naive "GET /?msg=..." style request
    size_t pos = req.find("msg=");
    string msg = "default";
    if (pos != string::npos) {
        msg = req.substr(pos + 4);
    }
    // echo back without sanitizing -> possible injection in certain contexts
    stringstream ss;
    ss << "HTTP/1.1 200 OK\r\n";
    ss << "Content-Type: text/plain\r\n";
    ss << "Set-Cookie: session=" << SECRET_TOKEN << "\r\n"; // leaking token in cookie
    ss << "\r\n";
    ss << "Echo: " << msg << "\n";
    return ss.str();
}

int main(int argc, char **argv) {
    cout << "Starting insecure network service simulator..." << endl;
    // read from a file as an example of input source
    if (argc > 1) {
        ifstream fin(argv[1]);
        if (fin) {
            string data((istreambuf_iterator<char>(fin)), istreambuf_iterator<char>());
            cout << handle_request(data) << endl;
        } else {
            cout << "Cannot open file" << endl;
        }
    } else {
        cout << "Provide input file with simulated request." << endl;
    }
    return 0;
}

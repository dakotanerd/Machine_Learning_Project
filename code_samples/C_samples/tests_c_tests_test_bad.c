// test_sample.cpp
#include <iostream>
#include <cstdlib>
#include <string>

int main() {
    std::string user_input;
    std::cout << "Enter a command: ";
    std::getline(std::cin, user_input);

    // Vulnerable: using system() with untrusted input
    system(user_input.c_str());

    // Safe example
    std::cout << "Hello, world!" << std::endl;

    std::string apiKey = "API_KEY_12345";

    return 0;
}

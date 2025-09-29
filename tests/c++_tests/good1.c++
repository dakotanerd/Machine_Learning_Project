// test_sample_fixed.cpp
#include <iostream>
#include <cstdlib>
#include <string>
#include <vector>
#include <sstream>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstring>

// split string on spaces (simple)
static std::vector<std::string> split_args(const std::string &s) {
    std::istringstream iss(s);
    std::vector<std::string> out;
    std::string token;
    while (iss >> token) out.push_back(token);
    return out;
}

int main() {
    std::string user_input;
    std::cout << "Enter a command (allowed: date, uptime): ";
    if (!std::getline(std::cin, user_input)) {
        std::cerr << "No input\n";
        return 1;
    }

    // --- Whitelist of allowed commands (use full absolute paths) ---
    // Only commands listed here may be executed, with controlled args.
    // Map short command name -> full path
    const std::unordered_map<std::string, std::string> whitelist = {
        {"date", "/bin/date"},
        {"uptime", "/usr/bin/uptime"}
    };

    auto args = split_args(user_input);
    if (args.empty()) {
        std::cerr << "Empty command\n";
        return 1;
    }

    const std::string &cmd_name = args[0];
    auto it = whitelist.find(cmd_name);
    if (it == whitelist.end()) {
        std::cerr << "Command not allowed.\n";
        return 1;
    }

    // Build argv for execv: argv[0] = full path or base name, argv[N] = args..., argv[last] = NULL
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(it->second.c_str())); // execv requires char*
    for (size_t i = 1; i < args.size(); ++i) {
        argv.push_back(const_cast<char*>(args[i].c_str()));
    }
    argv.push_back(nullptr);

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return 1;
    } else if (pid == 0) {
        // Child: execute the allowed command
        execv(it->second.c_str(), argv.data());
        // If execv returns, it failed:
        perror("execv");
        _exit(127);
    } else {
        // Parent: wait and report status
        int status = 0;
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            return 1;
        }
        if (WIFEXITED(status)) {
            std::cout << "Child exited with code " << WEXITSTATUS(status) << "\n";
        } else if (WIFSIGNALED(status)) {
            std::cout << "Child killed by signal " << WTERMSIG(status) << "\n";
        }
    }

    std::cout << "Hello, world!" << std::endl;

    // --- Get API key from environment at runtime (do NOT hardcode) ---
    const char* api_key = std::getenv("API_KEY");
    if (!api_key) {
        std::cerr << "Warning: API_KEY is not set in environment\n";
        // handle missing key appropriately
    } else {
        // Use api_key securely (do not print it).
        // e.g., pass to library that requires it.
    }

    return 0;
}

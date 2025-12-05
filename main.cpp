#include "analyzer.hpp"
#include "breach.hpp"
#include <iostream>
#include <fstream>
#include <vector>

using namespace std;

/*
  print_single:
  - Analyze one password (TEST STRING) and print a small report table
*/

    static void print_single(const string& pw, const string& site){
    auto a = analyze_password(pw, site);

    // Show the SHA-1 hash so we can prove we're hashing locally
    string hash = sha1_hex_upper(pw);
    cout << "[DEBUG] SHA-1 hash of this TEST password is: " << hash << "\n";
    cout << "[DEBUG] Prefix (first 5 chars) sent to API: " << hash.substr(0,5) << "\n\n";

    // Try breach check. If network fails, keep going with local analysis.
    bool found=false; int count=0;
    try {
        auto res = pwned_count(pw);
        found = res.first; count = res.second;
    } catch (const exception& e){
        cerr << "[!] Breach check error: " << e.what()
             << " (continuing with local analysis only)\n";
    }

    cout << "\nPassword Strength & Breach Check — TEST STRINGS ONLY\n";
    cout << "+---------------------------+--------------------------+\n";
    cout << "| Field                     | Value                    |\n";
    cout << "+---------------------------+--------------------------+\n";
    cout << "| Rating                    | " << a.rating << "\n";
    cout << "| Score                     | " << a.score  << "\n";
    cout << "| Length                    | " << a.length << "\n";
    cout << "| Charset Variety (0-4)     | " << a.variety << "\n";
    cout << "| Breach Found              | " << (found ? "YES" : "NO") << "\n";
    cout << "| Breach Count              | " << (found ? count : 0) << "\n";
    cout << "+---------------------------+--------------------------+\n";

    if (!a.reasons.empty()){
        cout << "\nReasons:\n";
        for (auto& r : a.reasons) cout << " - " << r << "\n";
    }
    if (!a.suggestions.empty()){
        cout << "\nSuggestions:\n";
        for (auto& s : a.suggestions) cout << " - " << s << "\n";
    }
    cout << endl;
}

/*
  print_file:
  - Read many test strings from a text file (one per line),
    run analysis + breach check for each, and print a table.
*/
static void print_file(const string& path, const string& site){
    ifstream in(path);
    if (!in){
        cerr << "Could not open: " << path << "\n";
        return;
    }
    vector<string> lines;
    string line;
    while (getline(in, line)){
        if (!line.empty()) lines.push_back(line);
    }

    cout << "\nPassword Strength & Breach Check — TEST STRINGS ONLY\n";
    cout << "+----------------------------------------------------------------------------------------------+\n";
    cout << "| Password (test)                 | Rating | Score | Len | Var | Breached | Count | Reasons     |\n";
    cout << "+----------------------------------------------------------------------------------------------+\n";

    for (const auto& pw : lines){
        auto a = analyze_password(pw, site);

        bool found=false; int count=0;
        try { auto res = pwned_count(pw); found=res.first; count=res.second; }
        catch (...) { /* keep found=false */ }

        // Simple fixed-width columns so it looks neat in terminal
        cout << "| " << pw;
        if (pw.size() < 30) cout << string(30 - pw.size(), ' ');
        cout << " | " << a.rating;
        if (a.rating.size() < 6) cout << string(6 - a.rating.size(), ' ');
        cout << " | " << a.score
             << "    | " << a.length
             << "   | " << a.variety
             << "   | " << (found ? "YES" : "NO ")
             << "     | " << (found ? count : 0)
             << "     | ";
        if (!a.reasons.empty()){
            cout << a.reasons[0];
        }
        cout << " |\n";
    }
    cout << "+----------------------------------------------------------------------------------------------+\n";
    cout << endl;
}

/*
  CLI usage:
    ./pw_checker "Password123" --site bank
    ./pw_checker --file tests/sample_passwords.txt --site reddit
*/
int main(int argc, char** argv){
    string pw, file, site;

    for (int i=1;i<argc;++i){
        string arg = argv[i];
        if (arg == "--file" && i+1<argc) file = argv[++i];
        else if (arg == "--site" && i+1<argc) site = argv[++i];
        else if (pw.empty()) pw = arg; // first positional argument is the password
    }

    if (!file.empty()){
        print_file(file, site);
        return 0;
    }
    if (!pw.empty()){
        print_single(pw, site);
        return 0;
    }

    cout << "Usage:\n"
         << "  " << argv[0] << " \"Password123\" --site bank\n"
         << "  " << argv[0] << " --file tests/sample_passwords.txt --site reddit\n";
    return 0;
}


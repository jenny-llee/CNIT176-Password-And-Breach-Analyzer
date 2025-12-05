#include "breach.hpp"
#include <openssl/sha.h>   // SHA1 from OpenSSL
#include <curl/curl.h>     // libcurl for HTTPS GET
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>

using namespace std;

/*
  libcurl writes response data by calling a callback we provide.
  Here we just append the downloaded bytes into a std::string.
*/
static size_t write_cb(void* ptr, size_t size, size_t nmemb, void* userdata){
    auto* out = static_cast<string*>(userdata);
    out->append(static_cast<char*>(ptr), size*nmemb);
    return size*nmemb;
}

/*
  sha1_hex_upper(s) -> compute SHA-1 of s, return uppercase hex string of length 40.
  We do hashing LOCALLY — we never send the password to the server.
*/
string sha1_hex_upper(const string& s){
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(s.data()), s.size(), digest);
    ostringstream oss;
    for (int i=0;i<SHA_DIGEST_LENGTH;++i){
        oss << uppercase << hex << setw(2) << setfill('0') << (int)digest[i];
    }
    return oss.str();
}

/*
  http_get_range(prefix5) -> GET https://api.pwnedpasswords.com/range/<prefix5>
  The server returns many lines like "SUFFIX:COUNT".
  We will match locally using our full hash suffix.
*/
static string http_get_range(const string& prefix5){
    string url = "https://api.pwnedpasswords.com/range/" + prefix5;

    CURL* curl = curl_easy_init();
    if (!curl) throw runtime_error("curl_easy_init failed");

    string body;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "PiPwChecker-Cpp/1.0 (Raspberry Pi)");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) throw runtime_error("curl perform failed");
    if (http_code != 200) throw runtime_error("HTTP status " + to_string(http_code));
    return body;
}

/*
  pwned_count(password):
  1) Hash password locally -> full 40-char uppercase hex.
  2) Split into prefix (first 5 chars) and suffix (remaining 35).
  3) Send ONLY the prefix to the API (privacy-preserving).
  4) Compare returned suffixes locally — if match, return (true, count).
*/
pair<bool,int> pwned_count(const string& password){
    string full = sha1_hex_upper(password);
    string prefix = full.substr(0,5);
    string suffix = full.substr(5); // 35 chars

    string body = http_get_range(prefix); // many lines "SUFFIX:COUNT"

    // Parse line by line and look for an exact suffix match
    size_t start = 0;
    while (true){
        size_t end = body.find('\n', start);
        string line = (end==string::npos) ? body.substr(start)
                                          : body.substr(start, end-start);
        if (!line.empty()){
            if (!line.empty() && line.back()=='\r') line.pop_back(); // remove CR if present
            size_t colon = line.find(':');
            if (colon!=string::npos){
                string suf = line.substr(0, colon);
                string cnt = line.substr(colon+1);
                if (suf == suffix){
                    try { int n = stoi(cnt); return {true, n}; }
                    catch (...) { return {true, 1}; }
                }
            }
        }
        if (end==string::npos) break;
        start = end + 1;
    }
    return {false, 0};
}


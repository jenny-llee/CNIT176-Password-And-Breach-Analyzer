#include "analyzer.hpp"
#include <algorithm>
#include <cctype>
#include <regex>
#include <string>

using namespace std;

/*
  Helper: check if string has at least one lowercase/uppercase/digit/special.
  We use these to count "variety."
*/
static bool any_lower(const string& s){return any_of(s.begin(), s.end(), ::islower);}
static bool any_upper(const string& s){return any_of(s.begin(), s.end(), ::isupper);}
static bool any_digit(const string& s){return any_of(s.begin(), s.end(), ::isdigit);}
static bool any_special(const string& s){
    return any_of(s.begin(), s.end(), [](unsigned char c){
        // ispunct means “punctuation”; good enough for "symbol"
        return ispunct(c) && !isalnum(c);
    });
}

// Make a lowercase copy (for case-insensitive checks)
static string lower(string s){
    transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

/*
  Detect digit sequences like "1234" or "4321".
  These are easy for attackers to guess.
*/
static bool has_seq_digits(const string& s, int L=4){
    const string digits = "0123456789";
    const string rev = "9876543210";
    if (s.size()<static_cast<size_t>(L)) return false;
    for (size_t i=0;i+L<=digits.size();++i)
        if (s.find(digits.substr(i,L))!=string::npos) return true;
    for (size_t i=0;i+L<=rev.size();++i)
        if (s.find(rev.substr(i,L))!=string::npos) return true;
    return false;
}

/*
  Detect keyboard "walks" like "qwer" or "asdf" (forward or backward).
*/
static bool has_keyboard_walk(const string& s, int L=4){
    static const char* rows[]={"qwertyuiop","asdfghjkl","zxcvbnm"};
    string low = lower(s);
    for (auto row: rows){
        string r(row);
        string rr = string(r.rbegin(), r.rend());
        for (size_t i=0;i+L<=r.size();++i)
            if (low.find(r.substr(i,L))!=string::npos) return true;
        for (size_t i=0;i+L<=rr.size();++i)
            if (low.find(rr.substr(i,L))!=string::npos) return true;
    }
    return false;
}

/*
  Main analyzer: add/subtract from "score", then bucket into a rating.
*/
Analysis analyze_password(const string& pw, const string& site_hint){
    Analysis a;
    a.length = static_cast<int>(pw.size());
    int score=0;
    vector<string> reasons, suggestions;

    // 1) Length
    if (a.length < 8) {
        reasons.push_back("Too short (<8)");
    } else if (a.length < 12) {
        reasons.push_back("Short (<12)");
        score += 1;
    } else if (a.length < 16) {
        score += 2;
    } else {
        score += 3;
    }

    // 2) Variety
    int variety = 0;
    if (any_lower(pw)) variety++;
    if (any_upper(pw)) variety++;
    if (any_digit(pw)) variety++;
    if (any_special(pw)) variety++;
    a.variety = variety;

    if (variety <= 1) {
        reasons.push_back("Needs more character variety");
    } else if (variety == 2) {
        score += 1;
    } else if (variety == 3) {
        score += 2;
    } else {
        score += 3;
    }

    // 3) Common words/patterns
    string low = lower(pw);
    static const vector<regex> COMMON = {
        regex("(password|letmein|qwerty|admin|welcome|iloveyou)"),
        regex("(12345|123456|1234567|12345678|123456789|111111|000000)")
    };
    for (const auto& re : COMMON){
        if (regex_search(low, re)){
            reasons.push_back("Contains common word/pattern (easily guessed)");
            score -= 2;
            break;
        }
    }

    // 4) Repeats (e.g., "aaa")
    for (size_t i=0;i+2<pw.size();++i){
        if (pw[i]==pw[i+1] && pw[i]==pw[i+2]){
            reasons.push_back("Contains repeated characters (e.g., aaa)");
            score -= 1;
            break;
        }
    }

    // 5) Digit sequences
    if (has_seq_digits(low, 4)){
        reasons.push_back("Contains digit sequence (e.g., 1234)");
        score -= 1;
    }

    // 6) Keyboard walks
    if (has_keyboard_walk(low, 4)){
        reasons.push_back("Keyboard sequence (e.g., qwerty)");
        score -= 1;
    }

    // 7) Years
    for (int y=1990;y<=2030;++y){
        auto ys = to_string(y);
        if (low.find(ys)!=string::npos){
            reasons.push_back("Includes a common year");
            score -= 1; break;
        }
    }

    // 8) Site reuse
    if (!site_hint.empty()){
        auto sh = lower(site_hint);
        if (low.find(sh)!=string::npos){
            reasons.push_back("Contains site/app name (reuse risk)");
            score -= 1;
        }
    }

    // Buckets
    string rating;
    if (score <= 1) rating = "Weak";
    else if (score <= 3) rating = "Fair";
    else if (score <= 5) rating = "Good";
    else rating = "Strong";

    // Suggestions
    if (a.length < 14) suggestions.push_back("Use 14+ characters");
    if (variety < 3) suggestions.push_back("Mix upper/lower/digit/symbol");
    if (find(reasons.begin(), reasons.end(),
        "Contains common word/pattern (easily guessed)") != reasons.end())
        suggestions.push_back("Avoid common words or substitutions");
    if (find(reasons.begin(), reasons.end(),
        "Contains site/app name (reuse risk)") != reasons.end())
        suggestions.push_back("Do not include the site/app name");
    if (find(reasons.begin(), reasons.end(),
        "Includes a common year") != reasons.end())
        suggestions.push_back("Avoid years or dates");
    if (find(reasons.begin(), reasons.end(),
        "Contains digit sequence (e.g., 1234)") != reasons.end())
        suggestions.push_back("Avoid sequences like 1234 or 4321");

    a.score = score;
    a.rating = rating;
    a.reasons = move(reasons);
    a.suggestions = move(suggestions);
    return a;
}


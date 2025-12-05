#pragma once
#include <string>
#include <vector>

using namespace std;

/*
  Analysis = the result we produce for each password:
  - length: number of characters
  - variety: how many character types (lower/upper/digit/symbol) are present (0..4)
  - score: a numeric score we compute (higher is better)
  - rating: a friendly bucket name: Weak/Fair/Good/Strong
  - reasons: human-readable reasons for problems
  - suggestions: human-readable tips to improve
*/
struct Analysis {
    int length{};
    int variety{};
    int score{};
    string rating;
    vector<string> reasons;
    vector<string> suggestions;
};

/*
  analyze_password(pw, site_hint):
  - pw = the password string (TEST STRINGS ONLY — never real passwords)
  - site_hint = optional name like "bank" or "reddit" to detect reuse
*/
Analysis analyze_password(const string& pw, const string& site_hint = "");

#pragma once
#include <string>
#include <utility>

using namespace std;

/*
  pwned_count(password) returns:
  - first: true if password hash was seen in breaches; false otherwise
  - second: how many times it appeared (count)
*/
pair<bool, int> pwned_count(const string& password);

// Expose hash helper for testing if you want
string sha1_hex_upper(const string& s);

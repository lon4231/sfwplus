#pragma once

#include "headers.h"

std::string read_file(std::string path)
{
std::ostringstream output;
std::ifstream file=std::ifstream(path);
output<<file.rdbuf();
return output.str();
}

std::vector<std::string>split_string(const std::string&str,char delimiter) {
std::vector<std::string>tokens;
std::stringstream ss(str);
std::string token;
while (std::getline(ss,token,delimiter)) 
{tokens.push_back(token);}
return tokens;
}
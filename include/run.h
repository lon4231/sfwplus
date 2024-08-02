#pragma once

#include "headers.h"
#include "file.h"

void run_code(std::string path)
{
std::vector<std::string>sfw_lua_s=split_string(read_file("sfw.lua"),'\n');
sfw_lua_s[0]="FILE =\""+path+"\"\n";

for(char&chr:sfw_lua_s[0])
{
if(chr=='\\')
{chr='/';}
}


std::string sfw_lua;
for (std::string&line:sfw_lua_s)
{sfw_lua+=line+"\n";}



lua_State* L = luaL_newstate();
if(L==nullptr){return;}

luaL_openlibs(L);

if (luaL_loadstring(L,sfw_lua.c_str())||lua_pcall(L,0,0,0)) 
{
std::string error=lua_tostring(L,-1);
lua_close(L);
return;
}

lua_close(L);
}
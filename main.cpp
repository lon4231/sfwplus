#include "include/include.h"

std::string help_message=
"USAGE:\n"\
"add a path into the arguments to run your script\n"\
"-h print this message\n"\
"end of help\n";

std::string code_path;

int main(int argc,char*argv[])
{
if(argc<=1)
{
std::cout<<"please input an argument\n";
return -1;
}

for (int i=1;i<argc;++i)
{
if(argv[i][0]=='-')
{
switch (argv[i][1])
{
case 'h':std::cout<<help_message;return 0;break;
default:break;
}
}
else
{code_path=argv[i];}
}


run_code(code_path);

std::cout<<"\n\ncode ended\npress any key to exit....";
std::cin.ignore();

return 0;
}
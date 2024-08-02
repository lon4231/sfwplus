all:
	cls
	g++ main.cpp -o out/sfw.exe -Isrc/include -Lsrc/lib -lmingw32 -llua54
	cd out && sfw test.sfw
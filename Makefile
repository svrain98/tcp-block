all: tcp-block

tcp-block : tcp-block.o
	g++ -o tcp-block tcp-block.o -lpcap

tcp-block.o : tcp-block.cpp
	g++ -c -o tcp-block.o tcp-block.cpp

clean :
	rm -f tcp-block *.o

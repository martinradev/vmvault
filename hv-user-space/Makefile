CPPFLAGS=-O2 -std=c++14
INCLUDES=../uapi/

hv-user-space-program: hv-user-space-program.o
	g++ hv-user-space-program.o -static -o hv-user-space-program

hv-user-space-program.o: hv-user-space-program.cpp
	g++ -c $(CPPFLAGS) -I$(INCLUDES) hv-user-space-program.cpp -o hv-user-space-program.o


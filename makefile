CXX=g++
MYLIBS=-I./inc/ 
LDFLAGS=-lbfd -lcapstone
CXXFLAGS=-std=c++14 -g -Wall

SRC=./src/
TEST=./tester/

.PHONY: all clean setup

all: $(TEST)tester

$(TEST)tester: $(TEST)tester.o $(SRC)loader.o $(SRC)disassembler.o
	$(CXX) $(MYLIBS) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(TEST)tester.o: $(TEST)tester.cpp
	$(CXX) -c $(MYLIBS) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

$(SRC)loader.o: $(SRC)loader.cpp
	$(CXX) -c $(MYLIBS) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

$(SRC)disassembler.o: $(SRC)disassembler.cpp
	$(CXX) -c $(MYLIBS) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

setup:
	sudo apt install binutils-multiarch-dev libcapstone-dev

clean:
	rm $(TEST)tester
	rm $(TEST)*.o
	rm $(SRC)*.o
CXX=g++
MYLIBS=-I./inc/ 
LIBBFD=-lbfd
CXXFLAGS=-std=c++14 -g -Wall

SRC=./src/
TEST=./tester/

.PHONY: clean

all: $(TEST)tester

$(TEST)tester: $(TEST)tester.o $(SRC)loader.o
	$(CXX) $(MYLIBS) $(CXXFLAGS) -o $@ $^ $(LIBBFD)

$(TEST)tester.o: $(TEST)tester.cpp
	$(CXX) -c $(MYLIBS) $(CXXFLAGS) -o $@ $< $(LIBBFD)

$(SRC)loader.o: $(SRC)loader.cpp
	$(CXX) -c $(MYLIBS) $(CXXFLAGS) -o $@ $< $(LIBBFD)

clean:
	rm $(TEST)tester
	rm $(TEST)tester.o
	rm $(SRC)loader.o
INCLUDE = -Ilzfse/src

.PHONY: all

all: kerneldec

%.o: %.c
	gcc -Wall -MMD $(INCLUDE) -c $< -o $@

%.cpp.o: %.cpp
	g++ -Wall -MMD $(INCLUDE) -c $< -o $@

lzfse:
	git submodule init
	git submodule update

liblzfse.a: lzfse
	make -C lzfse
	cp lzfse/build/bin/liblzfse.a .

-include $(wildcard *.d)

kerneldec: kerneldec.cpp.o lzssdec.cpp.o main.o liblzfse.a
	g++ -Wall $(INCLUDE) $^ -o $@

clean: lzfse
	rm -f kerneldec lzfse.a *.o *.d
	make -C lzfse clean

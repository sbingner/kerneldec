all: kerneldec

bin:
	@mkdir bin

%.o: %.c
	gcc -MMD -c $< -o $@

%.cpp.o: %.cpp
	g++ -MMD -c $< -o $@

-include $(wildcard *.d)

kerneldec: kerneldec.cpp.o lzssdec.cpp.o main.o
	g++ $^ -o $@

clean:
	rm -f kerneldec *.o *.d

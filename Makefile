all: kerneldec

bin:
	@mkdir bin

%.o: %.cpp
	g++ -MMD -c $< -o $@

-include $(wildcard *.d)

kerneldec: kerneldec.o lzssdec.o
	g++ $^ -o $@

clean:
	rm -f kerneldec *.o *.d

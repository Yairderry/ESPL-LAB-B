all: Bubblesort 

Bubblesort: Bubblesort.o
	gcc -m32 -g -Wall -o Bubblesort Bubblesort.o 

Bubblesort.o: Bubblesort.c
	gcc -g -Wall -m32 -c -o Bubblesort.o Bubblesort.c 

.PHONY: clean

clean:
	rm -f *.o
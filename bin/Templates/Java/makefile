# Author : Florian Picca <florian.picca@oppida.fr>
# Date : December 2019
sources = $(wildcard *.java)
classes = $(sources:.java=.class)
dependencies=libs/currentLib
JFLAGS = -cp $(dependencies):.
JC = javac


default: all

all: $(classes)

%.class:%.java
	$(JC) $(JFLAGS) $<

clean:
	rm -rf *.class

# Author : Florian Picca <florian.picca@oppida.fr>
# Date : December 2019
sources = $(wildcard *.java)
classes = $(sources:.java=.class)
# The BouncyCastle jar files are downloaded from here :
# http://www.bouncycastle.org/archive/
# Take bcprov with the jdk 15 at least
# In case a class is not found during compilation, check that it is included in the jar you downloaded:
# jar tf libs/currentLib | grep -i ecnamedcurvespec
dependencies=libs/currentLib
JFLAGS = -cp $(dependencies):.
JC = javac


default: all

all: $(classes)

%.class:%.java
	$(JC) $(JFLAGS) $<

clean:
	rm -rf *.class


# run with java -cp .:libs/currentLib Version
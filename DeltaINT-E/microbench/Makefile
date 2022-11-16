-include Makefile.local

include mk/recipes.mk

DEPS :=
CLEAN :=

##############################################################################
# Compile, link, and install flags

CC := g++
#CFLAGS += -std=c++14 -O3 -g -Wall -Werror -march=native -fno-omit-frame-pointer
CFLAGS += -std=c++14 -O3 -g -Wall -march=native -fno-omit-frame-pointer
CFLAGS += $(EXTRA_CFLAGS)
CFLAGS_SHARED += $(CFLAGS) -fPIC

INCDIR += -I/usr/include

##############################################################################

# Utils

UTILS_OBJECTS :=

DEPS += hash.d
CLEAN += hash.o
UTILS_OBJECTS += hash.o
UTILS_SHARED_OBJECTS += hash.shared.o

##############################################################################

CPPFLAGS += $(INCDIR)
CPPFLAGS += $(EXTRA_CPPFLAGS)

##############################################################################

TARGETS := hashtime_test

hashtime_test: hashtime_test.o $(UTILS_OBJECTS) 
	$(LINK) $^ $(LDLIBS) -o $@
DEPS += hashtime_test.d
CLEAN += hashtime_test.o

all: $(TARGETS)
	rm -rf $(CLEAN) $(DEPS)

##############################################################################

clean:
	rm -rf $(CLEAN) $(DEPS) $(TARGETS)

.DEFAULT_GOAL := all
.PHONY: all clean

# Include dependencies
-include $(DEPS)

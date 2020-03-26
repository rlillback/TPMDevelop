CC = gcc
WARN_FLAGS = -Wall -Wextra
DEBUG_FLAGS = -Og 
C_STD = -std=gnu99
LIBS = -lcurl -lcrypto 
#TSSLIBS = -ltpm2tss -L/usr/lib/arm-linux-gnueabihf/engines-1.1/
TSSLIBS = -ltpm2tss -L/usr/lib/x86_64-linux-gnu/engines-1.1
LIBS = -lcrypto
OBJS = tpm2test.o base64.o
SUCCESS = echo " "; echo "Build completed successfully"; echo " ";
FAILURE = echo " "; echo "Build FAILED"; echo " ";

all: ${OBJS}
	$(info beginning build)
	@if ${CC} -o tpm2test $^ ${LIBS} ${TSSLIBS}; then\
		${SUCCESS}\
	else\
		${FAILURE}\
	fi

# now define the generic builds
%.o: %.c
	$(info compiling $^)
	- @${CC} ${WARN_FLAGS} ${DEBUG_FLAGS} ${C_STD} -c $^

# define the clean or delete commands
.PHONY: deleteallobs
	$(info deleting all object files)
	@for i in *.o; do \
		if [ -f $$i ]; then $(info deleting intermediate object files) rm $$i; fi; \
	done; 
	@if [ -f tpm2test ]; then $(info deleting tpm2test) rm tpm2test; fi;
	$(info *** All objects removed successfully ***)

.PHONY: cleanall
cleanall:
	$(info deleting all object files)
	@for i in *.o; do \
		if [ -f $$i ]; then $(info deleting intermediate object files) rm $$i; fi; \
	done; 
	@if [ -f tpm2test ]; then $(info deleting tpm2test) rm tpm2test; fi;
	$(info *** All objects removed successfully ***)
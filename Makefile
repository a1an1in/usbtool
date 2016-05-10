#makefile
LD_FLAGS := -pthread
CFLAGS += -g 
source := $(notdir $(shell find . -name '*.c'))
objects := $(patsubst %.c,%.o,$(source))
libusb:$(objects)
	$(CC)  $(LD_FLAGS)  $^  -o $@ 
	ctags -R .
	cscope -Rqb 

%.o:%.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $< 

.PHONY : clean
clean:
	rm -f $(objects) libusb tags cscope.*


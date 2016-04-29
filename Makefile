LD_FLAGS := -pthread
CFLAGS += -g 
source := $(notdir $(shell find . -name '*.c'))
objects := $(patsubst %.c,%.o,$(source))
libusb:$(objects)
	$(CC)  $(LD_FLAGS)  $^  -o $@ 

%.o:%.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $< 

tags:
	ctags -R .
cscope:
	cscope -Rqb 

.PHONY : clean
clean:
	rm -f $(objects) libusb tags cscope.*


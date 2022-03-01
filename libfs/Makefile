lib := libfs.a
objs := fs.o disk.o

all: $(lib)

CC = gcc

CFLAGS := -Wall -Wextra -Werror

CFLAGS	+= -MMD

ifneq ($(D),1)
CFLAGS	+= -O2
else
CFLAGS	+= -g
endif

deps := $(patsubst %.o,%.d,$(objs))
-include $(deps)

$(lib): $(objs)
	$(Q) ar rcs $(lib) $(objs)

%.o: %.c 
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(Q) rm -f $(lib) $(objs) $(deps)
OBJ := CProxy
CC := gcc
#如果是安卓编译
ifeq ($(ANDROID_DATA),/data)
	CFLAGS := -O3 -pie -Wall 
	SHELL = /system/bin/sh
else
	CFLAGS := -O3 -pthread -Wall 
endif

all : main.o conf.o tcp.o common.o httpdns.o common.o
	$(CC) $(CFLAGS) $(DEFS) -o $(OBJ) $^
	strip $(OBJ)
	-chmod 777 $(OBJ) 2>&-

.c.o : 
	$(CC) $(CFLAGS) $(DEFS) -c $<

clean : 
	rm -f *.o

.PHONY: all clean distclean mkdirs

CC = gcc
LD = gcc
AR = ar

#-----------------------------------------------------------------------------

# BUILD directory
ifndef BUILD
    ifdef DEBUG
        BUILD := build/debug
    else
        BUILD := build/release
    endif
endif

#-----------------------------------------------------------------------------

LIBPDP = ../libpdp
LIBPDP_SRC = $(LIBPDP)/src
INCLUDES  = -Iinc -I$(LIBPDP)/inc
INCLUDES += -I$(LIBPDP)/inc/apdp -I$(LIBPDP)/inc/mrpdp -I$(LIBPDP)/inc/cpor -I$(LIBPDP)/inc/macpdp -I$(LIBPDP)/inc/sepdp

CFLAGS = -Wall -g $(INCLUDES)
CFLAGS += -D_FILE_OFFSET_BITS=64
CFLAGS += -D_THREAD_SUPPORT
ifdef DEBUG
    CFLAGS += -D_PDP_DEBUG
endif

LDFLAGS   = -lcrypto -pthread -lcurl -lcrypto -lxml2 -lz

#-----------------------------------------------------------------------------

LIBPDPGO = $(BUILD)/lib/libpdpgo.a

OBJS  = pdp_generic.o pdp_misc.o pdp_key.o pdp_file.o pdp_s3.o
OBJS += macpdp.o macpdp_key.o macpdp_file.o macpdp_s3.o
OBJS += apdp.o apdp_key.o apdp_file.o apdp_s3.o apdp_serialize.o
OBJS += mrpdp.o mrpdp_key.o mrpdp_file.o mrpdp_s3.o mrpdp_serialize.o
OBJS += cpor.o cpor_key.o cpor_file.o cpor_s3.o cpor_serialize.o
OBJS += sepdp.o sepdp_key.o sepdp_file.o sepdp_s3.o sepdp_serialize.o
OBJS += pdpgo.o

all: mkdirs headers $(LIBPDPGO)

mkdirs:
	@ mkdir -p $(BUILD)/lib
	@ mkdir -p $(BUILD)/obj

clean:
	rm -rf $(BUILD)/obj/*.o

distclean: clean
	rm -rf $(LIBPDPGO)

$(BUILD)/obj/%.o: src/%.c
	$(CC) -c $(CFLAGS) $< -o $@

$(BUILD)/obj/%.o: $(LIBPDP_SRC)/%.c
	$(CC) -c $(CFLAGS) $< -o $@

$(BUILD)/obj/%.o: $(LIBPDP_SRC)/apdp/%.c
	$(CC) -c $(CFLAGS) $< -o $@

$(BUILD)/obj/%.o: $(LIBPDP_SRC)/cpor/%.c
	$(CC) -c $(CFLAGS) $< -o $@

$(BUILD)/obj/%.o: $(LIBPDP_SRC)/macpdp/%.c
	$(CC) -c $(CFLAGS) $< -o $@

$(BUILD)/obj/%.o: $(LIBPDP_SRC)/mrpdp/%.c
	$(CC) -c $(CFLAGS) $< -o $@

$(BUILD)/obj/%.o: $(LIBPDP_SRC)/sepdp/%.c
	$(CC) -c $(CFLAGS) $< -o $@

$(LIBPDPGO): $(OBJS:%.o=$(BUILD)/obj/%.o)
	$(AR) rs $@ $^

headers:
	mkdir -p $(BUILD)/inc
	cp -r $(LIBPDP)/inc/* $(BUILD)/inc/
	cp -r inc/* $(BUILD)/inc/

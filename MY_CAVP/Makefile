CC = gcc
CFLAGS = -Wall -Wextra -O2 -I. -ICrypto_Alg/crypt_modules -ICrypto_Alg/Lea
TARGET = MY_CAVP/MY_cavp

SRCS = cavp_main.c \
       cavp_module.c \
       Crypto_Alg/crypt_modules/crypto_modules.c \
       Crypto_Alg/Lea/lea.c

OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

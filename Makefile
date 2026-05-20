CC      = clang
CFLAGS  = -std=c99 -Wall -Wextra -g \
           -Ivendor -Isrc \
           -I/opt/homebrew/opt/openssl@3/include \
           -DMG_ENABLE_LOG=0
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto

SRCS = src/main.c src/handlers.c src/webauthn.c \
       src/db.c src/crypto.c src/cbor.c \
       vendor/cJSON.c vendor/mongoose.c

OBJS = $(SRCS:.c=.o) vendor/sqlite3.o

TARGET = passkey-server

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

vendor/sqlite3.o: vendor/sqlite3.c
	$(CC) -std=c99 -O2 \
	  -DSQLITE_THREADSAFE=0 \
	  -DSQLITE_DEFAULT_MEMSTATUS=0 \
	  -c vendor/sqlite3.c -o vendor/sqlite3.o

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) passkeys.db

vendor-fetch:
	curl -sL https://raw.githubusercontent.com/cesanta/mongoose/master/mongoose.c -o vendor/mongoose.c
	curl -sL https://raw.githubusercontent.com/cesanta/mongoose/master/mongoose.h -o vendor/mongoose.h
	curl -sL https://raw.githubusercontent.com/DaveGamble/cJSON/master/cJSON.c    -o vendor/cJSON.c
	curl -sL https://raw.githubusercontent.com/DaveGamble/cJSON/master/cJSON.h    -o vendor/cJSON.h
	curl -sL https://www.sqlite.org/2024/sqlite-amalgamation-3460100.zip -o /tmp/sqlite.zip
	unzip -j /tmp/sqlite.zip "*/sqlite3.c" "*/sqlite3.h" -d vendor/

.PHONY: all clean vendor-fetch

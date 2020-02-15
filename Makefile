NAME   = hd-wallet
CC     ?= gcc

CFLAGS = -Wall -Werror -Wextra
CFLAGS += -std=c11 -pedantic
CFLAGS += -D_POSIX_C_SOURCE=200809L
CFLAGS += -I.

ifeq ($(SAN),yes)
	LDFLAGS += -fsanitize=address
	CFLAGS += -g -fsanitize=address -fno-omit-frame-pointer -fno-optimize-sibling-calls
endif


# Sources
SOURCES    += main.c
SOURCES    += utils.c
SOURCES    += node.c
SOURCES    += ckd.c
SOURCES    += wrappers.c

OBJ_PATH   = .obj
OBJECTS    = $(SOURCES:%.c=$(OBJ_PATH)/%.o)

# base58
CFLAGS     += -I/libbase58
LDFLAGS    += -Llibbase58/.libs -Wl,-rpath,libbase58/.libs -lbase58

# sodium
CFLAGS     += -Ilibsodium/src/libsodium/include/
LDFLAGS    += -Llibsodium/src/libsodium/.libs -Wl,-rpath,libsodium/src/libsodium/.libs -lsodium

# secp256k1
CFLAGS     += -Isecp256k1/include -Isecp256k1/src -DHAVE___INT128 -DUSE_SCALAR_4X64 -DUSE_NUM_GMP -DUSE_SCALAR_INV_BUILTIN -g -O2 -W -Wcast-align -Wnested-externs -Wshadow -Wstrict-prototypes -Wno-unused-function -Wno-long-long -Wno-overlength-strings -fvisibility=hidden -O3
LDFLAGS    += -Lsecp256k1/.libs -Wl,-rpath,secp256k1/.libs -lsecp256k1


all: $(NAME)

$(NAME): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(OBJECTS): $(OBJ_PATH)/%.o: %.c | $(OBJ_PATH)
	$(CC) $(CFLAGS) -o $@ -c $<

$(OBJ_PATH):
	@-mkdir -p $@

clean:
	$(RM) -r $(OBJ_PATH)

fclean: clean
	$(RM) $(NAME)

re: fclean all

# Tool rules

sanitize:
	$(MAKE) re SAN=yes

unsanitize:
	$(MAKE) re

sub-init:
	git submodule update --init --recursive

sub-update:
	git submodule update --remote --recursive

.PHONY: all clean fclean re sanitize unsanitize sub-update sub-init

NAME   = hd-wallet
CC     ?= clang

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

OBJ_PATH   = .obj
OBJECTS    = $(SOURCES:%.c=$(OBJ_PATH)/%.o)

# Libraries
CFLAGS     += -I../libbase58
LDFLAGS    += -lsodium -lssl -lcrypto -lsecp256k1
LIBS       = ../libbase58/.libs/libbase58.a


all: $(NAME)

$(NAME): $(OBJECTS)
	$(CC) -o $@ $^ $(LIBS) $(LDFLAGS)

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

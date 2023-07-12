MAKE = make

# Directory names
INC_DIR =	include/
SRC_DIR =	src/
BIN_DIR =	bin/

# Compiler and compiler flags
CC = gcc
CFLAGS = -Wall -Wextra -Werror -I$(INC_DIR) -g -fsanitize=address
 
# Library and object file names
NAME = ft_strace
SRC_FILES = ft_strace.c \
			printer.c \
			utils.c \
			summary.c

# List of include directories
SRCS = $(addprefix $(SRC_DIR), $(SRC_FILES))
BINS = $(addprefix $(BIN_DIR), $(SRC_FILES:.c=.o))

# Default target
all: $(NAME)
# Build the library
$(NAME): $(BINS)
	$(CC) $(CFLAGS) -o $@ $^


# Build object files from C source files
$(BIN_DIR)%.o: $(SRC_DIR)%.c
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean up
clean:
	rm -f $(BINS)

fclean: clean
	rm -f $(NAME) $(LIB_LINK)

re: fclean all

# Default target does not correspond to a file
.PHONY: all clean fclean re test libft

CC      := gcc
RM      := rm -f
CFLAGS  := -Wall -Wextra -Werror
NAME    := ft_malcolm

MAN_DIR  := mandatory
MAN_SRCS := main.c error.c getter.c utils.c
MAN_OBJS := $(addprefix $(MAN_DIR)/, $(MAN_SRCS:.c=.o))

BON_DIR  := bonus
BON_SRCS := main.c error.c getter.c
BON_OBJS := $(addprefix $(BON_DIR)/, $(BON_SRCS:.c=.o))
XDP_ONESHOT      := $(BON_DIR)/xdp_prog.o
XDP_POISON	:= $(BON_DIR)/xdp_prog_poisoning.o

all: mandatory

mandatory: $(MAN_OBJS)
	$(CC) $(MAN_OBJS) -o $(NAME)

$(MAN_DIR)/%.o: $(MAN_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

bonus: $(XDP_ONESHOT) $(XDP_POISON) $(BON_OBJS)
	$(CC) $(BON_OBJS) -lbpf -o $(NAME)

$(XDP_ONESHOT): $(BON_DIR)/xdp_prog.c
	clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu \
		-c $(BON_DIR)/xdp_prog.c -o $(XDP_ONESHOT)

$(XDP_POISON): $(BON_DIR)/xdp_prog_poisoning.c
	clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu \
		-c $(BON_DIR)/xdp_prog_poisoning.c -o $(XDP_POISON)

$(BON_DIR)/%.o: $(BON_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(MAN_OBJS) $(BON_OBJS) $(XDP_ONESHOT) $(XDP_POISON)

fclean: clean
	$(RM) $(NAME)

re: fclean all

.PHONY: all mandatory bonus clean fclean re

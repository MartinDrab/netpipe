TARGET=netpipe
CFLAGS= -O3 -Wall --std=gnu99 -DNDEBUG -Wno-unused-function
OBJDIR=./obj

OBJ=\
	$(OBJDIR)/aes.o	\
	$(OBJDIR)/auth.o	\
	$(OBJDIR)/logging.o	\
	$(OBJDIR)/netpipe.o	\
	$(OBJDIR)/randomness.o	\
	$(OBJDIR)/sha2.o	\

INCLUDE= -I./ -I-

$(OBJDIR)/%.o : %.c
	@mkdir -p $(OBJDIR)
	@echo "Compiling $<"
	@$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

$(TARGET): $(OBJ)
	@echo "Linking $@"
	@$(CC) $^ $(LIBS) -o $@

all: $(TARGET)

clean:
	@rm -f $(OBJ)

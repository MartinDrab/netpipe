TARGET=netpipe
CFLAGS ?= -O3 -pipe
CFLAGS += -Wall --std=gnu99 -DNDEBUG -Wno-unused-function
OBJDIR=./obj

OBJ=\
	$(OBJDIR)/aes.o	\
	$(OBJDIR)/auth.o	\
	$(OBJDIR)/logging.o	\
	$(OBJDIR)/netpipe.o	\
	$(OBJDIR)/netpipe-app.o	\
	$(OBJDIR)/randomness.o	\
	$(OBJDIR)/sha2.o	\
	$(OBJDIR)/utils.o	\


.PHONY: all
all: $(TARGET)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) $(LDLIBS) -o $@


.PHONY: clean
clean:
	$(RM) $(OBJ) $(TARGET)

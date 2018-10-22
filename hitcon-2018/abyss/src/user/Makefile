TARGET := user.elf
all: $(TARGET)

$(TARGET): user.c
	$(CC) user.c -o $(TARGET) -fPIE -pie -Wl,-z,relro,-z,lazy
	# strip $(TARGET)

clean:
	$(RM) $(TARGET)


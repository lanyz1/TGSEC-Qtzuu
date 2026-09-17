SWIFTC ?= xcrun swiftc
SWIFTFLAGS ?= -O
TARGET := poc
SOURCE := poc.swift

.PHONY: all run clean

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(SWIFTC) $(SWIFTFLAGS) -framework IOKit -framework IOSurface -o $@ $<

run: $(TARGET)
	./$(TARGET)

clean:
	$(RM) $(TARGET)

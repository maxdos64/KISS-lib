CC=g++
LIB_DIR=./lib
BIN=./bin
SRC_DIR=./src
HEADER_DIR=./include
INCLUDE_DIR=./include
EXAMPLES_DIR=./examples
CFLAGS=-std=c++11 -fPIC -march=native -O2 -DNDEBUG -I$(INCLUDE_DIR)
LIBS=-lsdsl -ldivsufsort -ldivsufsort64 

DEPS=$(addprefix $(HEADER_DIR)/, search.h compress.h utils.h)
SRCS=search.cpp compress.cpp 
EXAMPLES=compress_example search_example

OBJS=$(addprefix $(BIN)/, $(SRCS:.cpp=.o))
TARGET_LIB=libkiss.so

.PHONY: all
#$(info $$OBJS is [${OBJS}])
all: lib examples

.PHONY: lib
lib: ${TARGET_LIB}

.PHONY: examples
examples: $(EXAMPLES)
# export LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):$(PWD)

$(BIN)/%.o: $(SRC_DIR)/%.cpp $(DEPS)
	@mkdir -p $(@D)
	$(CC) -c -o $@ $< $(CFLAGS) -L$(LIB_DIR) $(LIBS)

$(TARGET_LIB): $(OBJS)
	$(CC) -shared -o $@ $^ -L$(LIB_DIR) $(LIBS)

compress_example: $(EXAMPLES_DIR)/compress_example.cpp
	g++ -o $@ $< -std=c++11 -march=native -O2 -DNDEBUG -I$(INCLUDE_DIR) -L. -lkiss  -L$(LIB_DIR) $(LIBS)

search_example: $(EXAMPLES_DIR)/search_example.cpp
	g++ -o $@ $< -std=c++11 -march=native -O2 -DNDEBUG -I$(INCLUDE_DIR) -L. -lkiss  -L$(LIB_DIR) $(LIBS)

clean:
	rm -f $(BIN)/*.o $(EXAMPLES) $(TARGET_LIB)

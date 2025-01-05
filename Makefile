# Nome do compilador
CXX = clang++

# Flags do compilador
CXXFLAGS = -std=c++20 -O3 -pthread

# Diretórios de inclusão
INCLUDES = -I. -Iinclude

# Bibliotecas necessárias
LDFLAGS = -lcrypto -lssl -lsecp256k1 -pg 

# Nome do executável
TARGET = main

# Arquivos fontes
SRC = main.cpp
# Arquivos objetos gerados
OBJ = main.o
# Regra padrão para compilar
all: $(TARGET)

# Como gerar o binário
$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) $(OBJ) $(LDFLAGS) -o $(TARGET)



# Como compilar o arquivo IntMod.o


# Como compilar o arquivo main.o
main.o: main.cpp
	$(CXX) $(CXXFLAGS) -c main.cpp -o main.o

# Regra para limpar arquivos gerados
clean:
	rm -f $(TARGET) $(OBJ)

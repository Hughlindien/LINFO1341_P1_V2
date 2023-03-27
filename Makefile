CC= gcc -std=gnu99
CFLAGS= -Wall -Werror -g
LIBS = -lcunit -lm
PATH_GMSH_LIB_FILE= gmsh-sdk/lib/libgmsh.so
FLAGS_GMSH_LIB= -Wl,-rpath,gmsh-sdk/lib

compile : execute

execute : src/dns_traffic_analyse.py
	python3 src/dns_traffic_analyse.py

graph : src/dns_graph_vid.py
	python3 src/dns_graph_vid.py
clean :
	rm -f Images/*.pdf

.PHONY: execute graph clean

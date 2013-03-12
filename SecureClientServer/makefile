#Makefile for Heightmap Analyser
#(C) Benjamin Hugo

#Setup
JAVACPATH = javac
BINDIR = bin/
SRCDIR = src/
LIBRARIES_DIR = lib/
JARSDIR = lib/
#Define parameters for java and javac
PARAMS = -g -cp "$(SRCDIR)" -d $(BINDIR)
RUNPARAMS = -cp "$(BINDIR)"
.SUFFIXES: .java .class

#Tell make to look in the source folder
VPATH = $(SRCDIR) $(BINDIR)

#Compile driver:
.java.class:
	@if [ ! -d $(BINDIR) ]; then mkdir $(BINDIR); fi; $(JAVACPATH) $(PARAMS) $<
Driver.class:Driver.java Client.class Server.class KeyGenerator.class
KeyGenerator.class:KeyGenerator.java KeyringReader.class
KeyringReader.class:KeyringReader.java
ProtocolInfo.class:ProtocolInfo.java
Base64.class:Base64.java
NonBlockingReader.class:NonBlockingReader.java
TCPServerSocket.class:TCPServerSocket.java TCPSocket.class SocketListener.class
SocketListener.class:SocketListener.java
TCPSocket.class:TCPSocket.java SocketListener.class
Pair.class:Pair.java
CypherMachine.class:CypherMachine.java
TCPServerSocket.class:TCPServerSocket.java TCPSocket.class SocketListener.class
Client.class:Client.java TCPSocket.class SocketListener.class KeyringReader.class NonBlockingReader.class ProtocolInfo.class CypherMachine.class Base64.class
Server.class:Server.java TCPSocket.class TCPServerSocket.class Pair.class KeyringReader.class NonBlockingReader.class ProtocolInfo.class SocketListener.class CypherMachine.class
run:
	clear
	java $(RUNPARAMS) Driver
crun:
	make clean
	make
	make run
mod_keyring:
	clear
	java $(RUNPARAMS) KeyGenerator	
clean:
	@echo Cleaning out all class files. Stand by
	@if [ -d $(BINDIR) ]; then rm -r $(BINDIR); fi
	@echo Done.

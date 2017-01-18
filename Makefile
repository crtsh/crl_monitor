all: clean crl_monitor

# Tidy up files created by compiler/linker.
clean:
	rm -f crl_monitor

crl_monitor:
	GOPATH=/root/go go build crl_monitor.go processor_main.go

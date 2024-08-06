all: clean crl_monitor

# Tidy up files created by compiler/linker.
clean:
	rm -f crl_monitor

crl_monitor:
	go build -ldflags "-X main.build_date=`date -u +%Y-%m-%d.%H:%M:%S`" crl_monitor.go processor_main.go

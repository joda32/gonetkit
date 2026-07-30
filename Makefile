BINARY_DIR := build
LDFLAGS := -s -w
TOOLS := $(notdir $(wildcard cmd/*))
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: all clean release $(TOOLS)

all: $(TOOLS)

$(TOOLS):
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BINARY_DIR)/$@ ./cmd/$@

clean:
	rm -rf $(BINARY_DIR)

release: release-linux release-windows

release-linux: all
	tar -czf $(BINARY_DIR)/gonetkit-$(VERSION)-linux-amd64.tar.gz -C $(BINARY_DIR) $(TOOLS)

release-windows:
	$(foreach tool,$(TOOLS),GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BINARY_DIR)/$(tool).exe ./cmd/$(tool);)
	cd $(BINARY_DIR) && zip gonetkit-$(VERSION)-windows-amd64.zip $(addsuffix .exe,$(TOOLS))

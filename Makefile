lint:
	golangci-lint run

format:
	golangci-lint fmt

build:
	@for dir in ./cmd/*; do \
		name=$$(basename $$dir); \
		echo "Building $$name..."; \
		go build -o ./$$name $$dir; \
	done

clean:
	rm -f ./wsh ./wshd ./wcp ./wsh-keygen

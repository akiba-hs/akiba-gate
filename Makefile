# Короткие команды разработки. Полный цикл перед коммитом: make check
BINARY := akiba-gate

.PHONY: build test race cover fmt fmt-check vet check clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/$(BINARY) ./cmd/$(BINARY)

test:
	go test ./...

# Гонки ловятся только под -race, а у шлюза есть фоновые горутины: воркер
# загрузок (он же запускается и останавливается из HTTP-обработчиков) и
# отправка сообщений в чат.
race:
	go test -race -count=1 ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

vet:
	go vet ./...

# fmt правит файлы, fmt-check только сообщает. В check входит именно
# проверка: иначе цель молча переформатировала бы дерево и всегда проходила,
# в том числе в CI, где нарушение форматирования обязано ронять сборку.
fmt:
	gofmt -l -w .

fmt-check:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then echo "не отформатировано:"; echo "$$out"; exit 1; fi

check: fmt-check vet test race

clean:
	rm -rf bin coverage.out

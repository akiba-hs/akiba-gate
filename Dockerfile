# Сборка: статический бинарник без cgo.
# Драйвер SQLite взят из modernc.org — он на чистом Go, поэтому
# CGO_ENABLED=0 не мешает работе с базой.
FROM golang:1.27-alpine AS build

WORKDIR /src

# Зависимости отдельным слоем: пересобираются только при изменении go.mod/go.sum.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /out/akiba-gate ./cmd/akiba-gate

# Проверка образа: тесты гоняются в CI, но пусть сборка падает и здесь,
# если кто-то соберёт образ из сломанного дерева.
RUN CGO_ENABLED=0 go test ./...

# Итоговый образ: distroless, без шелла и пакетного менеджера.
FROM gcr.io/distroless/static-debian12:nonroot

# Каталог базы должен принадлежать пользователю nonroot (uid 65532),
# иначе шлюз не сможет создать gate.db в примонтированном томе.
WORKDIR /var/lib/akiba-gate
COPY --from=build --chown=nonroot:nonroot /out/akiba-gate /usr/local/bin/akiba-gate

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/akiba-gate"]

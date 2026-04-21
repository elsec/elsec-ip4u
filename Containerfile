FROM docker.io/library/alpine:3.21 AS build

RUN apk add --no-cache gcc musl-dev make

WORKDIR /src
COPY Makefile server.c ./
RUN make


FROM docker.io/library/alpine:3.21

WORKDIR /app
COPY --from=build /src/server .

EXPOSE 8080

CMD ["./server"]

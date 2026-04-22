FROM docker.io/library/alpine:3.21 AS build

RUN apk add --no-cache gcc musl-dev make openssl-dev

WORKDIR /src
COPY Makefile server.c ./
RUN make


FROM docker.io/library/alpine:3.21

RUN apk add --no-cache openssl

WORKDIR /app
COPY --from=build /src/server .
COPY keygen .

EXPOSE 8080

CMD ["./server"]

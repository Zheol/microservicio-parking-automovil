FROM golang:1.22.3

WORKDIR /usr/src/app

COPY . .
RUN go mod tidy 

EXPOSE 8089

CMD ["go", "run", "main.go"]

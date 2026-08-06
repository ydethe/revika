#! /bin/bash

go test ./... -coverpkg=./... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html

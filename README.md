# Go Adventures

## Run
#### Commandline
```bash
go build main.go
```
#### Docker:
```bash
docker build -t mygo .
docker run -p 9000:9000 -d mygo
```

#### With Locust Test
incomplete.
```bash
cd locust
docker-compose build
docker-compose up
```

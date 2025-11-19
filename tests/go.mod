module github.com/lumiforge/sellerproof-backend/tests

go 1.24.2

require (
	github.com/lumiforge/sellerproof-backend v0.0.0
	google.golang.org/grpc v1.69.4
)

replace github.com/lumiforge/sellerproof-backend => ../

require (
	golang.org/x/net v0.46.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241015192408-796eee8c2d53 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
)

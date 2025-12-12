module goercer

go 1.24.1

require (
	github.com/jfjallid/go-smb v0.6.7
	golang.org/x/crypto v0.37.0
)

require (
	github.com/jfjallid/gofork v1.7.6 // indirect
	github.com/jfjallid/gokrb5/v8 v8.5.1 // indirect
	github.com/jfjallid/golog v0.3.3 // indirect
	github.com/jfjallid/mstypes v0.0.1 // indirect
	github.com/jfjallid/ndr v0.0.1 // indirect
	golang.org/x/net v0.39.0 // indirect
)

replace github.com/jfjallid/go-smb => ./go-smb-fork

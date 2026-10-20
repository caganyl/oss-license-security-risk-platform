module example.com/monorepo

go 1.21

require (
	example.com/monorepo/internal/auth v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.9.3
	github.com/old/fork v1.2.0
	github.com/pinned/lib v1.0.0 // indirect
	github.com/pinned/lib2 v1.5.0
	golang.org/x/crypto v0.23.0 // indirect
	github.com/winpath/mod v0.1.0
)

replace example.com/monorepo/internal/auth => ./internal/auth

replace (
	github.com/old/fork => github.com/new/fork v1.3.1
	github.com/pinned/lib v1.0.0 => github.com/pinned/lib v1.0.2
	github.com/pinned/lib => github.com/pinned/lib v9.9.9
	github.com/pinned/lib2 v1.4.0 => ../lib2
	golang.org/x/crypto => golang.org/x/crypto v0.24.0
	github.com/winpath/mod => C:\src\mod
)

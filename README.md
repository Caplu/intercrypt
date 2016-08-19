# intercrypt - Store encrypted files on IPFS

This is a simple demonstration of how encryption could be done in IPFS. Don't
expect it to be production ready.

You can only store a single file and it cannot be larger than about 4 MB.
Support for directories or larger files may be added later.

## Building

Build dependencies (if you haven't already):
```
go get github.com/ipfs/go-ipfs-api
go get github.com/ipfs/go-ipfs
cd $GOPATH/src/github.com/ipfs/go-ipfs
make install
```

Build intercrypt:
```
go get github.com/jakobvarmose/intercrypt
cd $GOPATH/src/github.com/jakobvarmose/intercrypt
go build
```

## Running

Make sure to start an IPFS daemon before running this program.

### Add a file
```
intercrypt add <filename>
```

### Download a file
```
intercrypt get <key> <secret>
```

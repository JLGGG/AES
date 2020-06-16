package aes

import "testing"

//Run command go test -bench . in GOPATH/src/aes
//The print* function in the aes function should be annotated before benchmark execution.
//Annotation No.504, 505, 541, 561, 562, 629 in aes_function.go
//go test -bench=. -benchtime=10000x : run benchmark function 10000 times.
func BenchmarkCBC(b *testing.B) {
	for i := 0; i < b.N; i++ {
		EncryptCbcMode([]byte{'t', 'e', 's', 't'}, []byte{'t'})
		DecryptCbcMode([]byte{'t'})
	}
}
func BenchmarkCTR(b *testing.B) {
	for i := 0; i < b.N; i++ {
		EncryptCtrMode([]byte{'t', 'e', 's', 't'}, []byte{'t'})
		DecryptCtrMode([]byte{'t'})
	}
}

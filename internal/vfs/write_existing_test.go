package vfs

import (
	"bytes"
	"testing"
)

// An existing file opened with CREAT but without TRUNC, then closed with no
// writes, must keep its contents. A write-less close may only create an empty
// file when the file is new or truncation was requested.
func TestCreatWithoutTruncOnExistingFileKeepsContents(t *testing.T) {
	fx := newFixture(t, nil, Options{}, testServers)
	original := []byte("server.properties contents")
	fx.api.seedFile(testNS, "survival", "/keep.properties", original)

	w, err := fx.fs.Filewrite(openReq("/survival/keep.properties", fxfWrite|fxfCreat))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	closeOrFail(t, w)

	got, ok := fx.api.fileData(testNS, "survival", "/keep.properties")
	if !ok {
		t.Fatalf("existing file was removed by a write-less CREAT close")
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("existing file changed by a write-less CREAT close: got %q, want %q", got, original)
	}
}

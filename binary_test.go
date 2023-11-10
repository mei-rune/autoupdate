package autoupdate

import (
	"bytes"
	"io/ioutil"
	//"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"archive/zip"
)

func TestBinary(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "bin-test-")
	if err != nil {
		t.Error(err)
		return
	}
	// defer os.RemoveAll(tempDir)

	filename1 := filepath.Join(tempDir, "t1")
	filename2 := filepath.Join(tempDir, "t2")
	if runtime.GOOS == "windows" {
		filename1 = filepath.Join(tempDir, "t1.exe")
		filename2 = filepath.Join(tempDir, "t2.exe")
	}

	cmd := exec.Command("go", "build", "-o", filename1)
	cmd.Dir = "test_data"
	bs, err := cmd.CombinedOutput()
	if err != nil {
		t.Log(string(bs))
		t.Error(err)
		return
	}

	zipFile := ".\\test_data\\file.zip"

	err = EmbedFile(filename1, filename2, zipFile)
	if err != nil {
		t.Error(err)
		return
	}

	cmd = exec.Command(filename2)
	bs, err = cmd.CombinedOutput()
	if err != nil {
		t.Log(string(bs))
		t.Error(err)
		return
	}

	bs = bytes.TrimSpace(bs)

	r, err := zip.OpenReader(zipFile)
	if err != nil {
		t.Error(err)
		return
	}
	defer r.Close()

	cr, err := r.Open("file.txt")
	if err != nil {
		t.Error(err)
		return
	}

	expect, err := ioutil.ReadAll(cr)
	if err != nil {
		t.Error(err)
		return
	}

	expect = bytes.TrimSpace(expect)
	if !bytes.Equal(bs, expect) {
		t.Error("want", string(expect))
		t.Error(" got", string(bs))
	}
}

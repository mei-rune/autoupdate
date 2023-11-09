package autoupdate

import (
	"io/ioutil"
	//"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
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

	err = EmbedFile(filename1, filename2, ".\\file.zip")
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

	t.Log(string(bs))
}

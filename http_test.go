package autoupdate

import (
	"context"
	"io/ioutil"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestSimple1(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "patchs-test-")
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(tempDir)
	if false {
		defer os.RemoveAll(tempDir)
	}

	hs, err := NewHTTPServer(tempDir, "", "")
	if err != nil {
		t.Error(err)
		return
	}

	hsrv := httptest.NewServer(hs)
	defer hsrv.Close()

	u, _ := url.Parse(hsrv.URL)

	err = DeployWithReader(nil, nil, hsrv.URL+"/testrepo/1.2.3", "windows_amd64.zip", strings.NewReader("abc1"))
	if err != nil {
		t.Error(err)
		return
	}

	err = DeployWithReader(nil, nil, hsrv.URL+"/testrepo/1.2.3", "linux_amd64.tar.gz", strings.NewReader("abc2"))
	if err != nil {
		t.Error(err)
		return
	}

	client := &HTTPClient{
		BaseURL: u,
	}

	ctx := context.Background()
	pkgs, err := client.Read(ctx, "testrepo")
	if err != nil {
		t.Error(err)
		return
	}

	expected := []AvailableUpdate{
		{
			Version: "1.2.3",
			List: []PackageInfo{
				{
					Arch:     "linux_amd64",
					Filename: "linux_amd64.tar.gz",
					URLPath:  "testrepo/1.2.3/linux_amd64.tar.gz",
					SUM:      "S90Lv+P0xSzCyP8C8f7ylmPdmTjyMDBJFYBa8fpx6Wg=",
				},
				{
					Arch:     "windows_amd64",
					Filename: "windows_amd64.zip",
					URLPath:  "testrepo/1.2.3/windows_amd64.zip",
					SUM:      "2/z9DYciD2KTOb063PRS0IP94yRmJfs6k+MU+DPiDTc=",
				},
			},
		},
	}

	if !cmp.Equal(expected, pkgs) {
		txt := cmp.Diff(expected, pkgs)
		t.Error(txt)
	}

	downloadDir, err := ioutil.TempDir("", "download-test-")
	if err != nil {
		t.Error(err)
		return
	}
	if true {
		defer os.RemoveAll(downloadDir)
	}
	dfilename, err := client.RetrievePackage(ctx, expected[0].List[0], downloadDir)
	if err != nil {
		t.Error(err)
		return
	}
	if name := filepath.Base(dfilename); name != expected[0].List[0].Filename {
		t.Error("filename want", expected[0].List[0].Filename, "got", name)
		return
	}

	dfilename, err = client.RetrievePackage(ctx, expected[0].List[1], downloadDir)
	if err != nil {
		t.Error(err)
		return
	}
	if name := filepath.Base(dfilename); name != expected[0].List[1].Filename {
		t.Error("filename want", expected[0].List[1].Filename, "got", name)
		return
	}

	pkgInfo := expected[0].List[1]
	pkgInfo.SUM = "ABC"

	dfilename, err = client.RetrievePackage(ctx, pkgInfo, downloadDir)
	if err == nil {
		t.Error("want error got ok")
		return
	}
	if !strings.Contains(err.Error(), "文件 sum 不正确") {
		t.Error(err)
		return
	}
}

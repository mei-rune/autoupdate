package autoupdate

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	jwt "github.com/golang-jwt/jwt/v4"
)

type HTTPClient struct {
	BaseURL *url.URL
	Client  *http.Client
	Hasher  Hasher

	publicKey     crypto.PublicKey
	signingMethod jwt.SigningMethod
}

func (c *HTTPClient) LoadSigningMethod(alg, keyFile string) error {
	if keyFile != "" {
		key, err := LoadPublicKey(keyFile)
		if err != nil {
			return err
		}

		c.publicKey = key
	}
	if alg == "" {
		alg = GetDefaultSignMethod()
	}
	c.signingMethod = jwt.GetSigningMethod(alg)
	return nil
}

var insecureClient = &http.Client{
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
}

func GetDefaultHttpClient() *http.Client {
	return insecureClient
}

func (c *HTTPClient) Read(ctx context.Context, repo string) ([]AvailableUpdate, error) {
	client := c.Client
	if client == nil {
		client = GetDefaultHttpClient()
	}

	urlstr := c.BaseURL.JoinPath(repo).String()
	response, err := client.Get(urlstr)
	if err != nil {
		return nil, err
	}
	if response.Body != nil {
		defer func(rc io.ReadCloser) {
			io.CopyN(ioutil.Discard, rc, 1<<30)
			rc.Close()
		}(response.Body)
	}

	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusNotFound {
			return nil, errors.New("GET '" + urlstr + "', " + response.Status)
		}
		if response.Body != nil {
			bs, _ := ioutil.ReadAll(response.Body)
			if len(bs) > 0 {
				return nil, errors.New(string(bs))
			}
		}
		return nil, errors.New(response.Status)
	}

	bs, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.New("读数据失败: " + err.Error())
	}

	sig := response.Header.Get(xsignKey)
	if sig == "" {
		if c.signingMethod != nil {
			return nil, errors.New("响应中缺少数据签名")
		}
	} else {
		if c.signingMethod == nil {
			return nil, errors.New("本地没有指定数据签名的算法")
		}
		err = c.signingMethod.Verify(string(bs), sig, c.publicKey)
		if err != nil {
			return nil, errors.New("校验数据签名失败: " + err.Error())
		}
	}

	var list []AvailableUpdate
	err = json.Unmarshal(bs, &list)
	if err != nil {
		return nil, errors.New("读数据失败: " + err.Error())
	}
	return list, nil
}

func (c *HTTPClient) DownloadKeyFile(ctx context.Context, repo string) (string, error) {
	client := c.Client
	if client == nil {
		client = GetDefaultHttpClient()
	}

	response, err := client.Get(c.BaseURL.JoinPath(repo, "/pub.pem").String())
	if err != nil {
		return "", err
	}
	if response.Body != nil {
		defer func(rc io.ReadCloser) {
			io.CopyN(ioutil.Discard, rc, 1<<30)
			rc.Close()
		}(response.Body)
	}

	if response.StatusCode != http.StatusOK {
		if response.Body != nil {
			bs, _ := ioutil.ReadAll(response.Body)
			if len(bs) > 0 {
				return "", errors.New(string(bs))
			}
		}
		return "", errors.New(response.Status)
	}

	bs, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", errors.New("读数据失败: " + err.Error())
	}
	return string(bs), nil
}

func (c *HTTPClient) RetrievePackage(ctx context.Context, info PackageInfo, dir string) (string, error) {
	var err error
	for i := 0; ; i++ {
		if i >= 3 {
			return "", err
		}

		filename, e := c.download(ctx, info, dir)
		if e != nil {
			err = e
			continue
		}

		hasher := c.Hasher
		if hasher == nil {
			hasher = defaultHasher
		}
		ok, e := VerifyFile(hasher, filename, info.SUM)
		if e == nil {
			if ok {
				return filename, nil
			}
			return "", errors.New("文件 sum 不正确")
		}
		err = e
	}
}

func (c *HTTPClient) download(ctx context.Context, info PackageInfo, dir string) (string, error) {
	client := c.Client
	if client == nil {
		client = GetDefaultHttpClient()
	}
	response, err := client.Get(c.BaseURL.JoinPath(info.URLPath).String())
	if err != nil {
		return "", err
	}
	if response.Body != nil {
		defer func(rc io.ReadCloser) {
			io.CopyN(ioutil.Discard, rc, 1<<30)
			rc.Close()
		}(response.Body)
	}

	if response.StatusCode != http.StatusOK {
		if response.Body != nil {
			bs, _ := ioutil.ReadAll(response.Body)
			if len(bs) > 0 {
				return "", errors.New(string(bs))
			}
		}
		return "", errors.New(response.Status)
	}

	contentType := response.Header.Get("Content-Type")
	if contentType != "" &&
		contentType != "application/octet-stream" &&
		contentType != "application/x-zip-compressed" &&
		contentType != "application/x-gzip" {
		return "", errors.New("文件的 content-type 不正确 - '" + contentType + "'")
	}

	filename := filepath.Join(dir, filepath.Base(info.URLPath))
	err = copyReaderToFile(response.Body, filename)
	if err != nil {
		return "", err
	}
	return filename, nil
}

func DeployWithHasher(client *http.Client, hasher Hasher, u string, filename string) error {
	if hasher == nil {
		hasher = defaultHasher
	}

	return deploy(client, u, func(mw *multipart.Writer) error {
		return writeFile(mw, filename)
	}, func(mw *multipart.Writer) error {
		sum, err := SumFile(hasher, filename)
		if err != nil {
			return err
		}
		return mw.WriteField("sum", sum)
	})
}

func DeployWithReader(client *http.Client, hasher Hasher, u string, filename string, reader io.Reader) error {
	if hasher == nil {
		hasher = defaultHasher
	}
	hw := hasher.New()

	return deploy(client, u, func(mw *multipart.Writer) error {
		return writeFromReader(mw, filename, io.TeeReader(reader, hw))
	}, func(mw *multipart.Writer) error {
		sum, err := hw.Sum()
		if err != nil {
			return err
		}
		return mw.WriteField("sum", sum)
	})
}

func DeployWithOnlyPackageFile(client *http.Client, hasher Hasher, u string, filename string) error {
	//打开文件句柄操作
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return DeployWithReader(client, hasher, u, filename, file)
}

func Deploy(client *http.Client, u string, filename, sumfilename string) error {
	if sumfilename != "" {
		if ext := filepath.Ext(sumfilename); ext != ".sum" {
			return errors.New("sum 文件格式不支持")
		}
	}

	return deploy(client, u, func(mw *multipart.Writer) error {
		return writeFile(mw, filename)
	}, func(mw *multipart.Writer) error {
		if sumfilename != "" {
			fileWriter, err := mw.CreateFormFile(filepath.Base(sumfilename), filepath.Base(sumfilename))
			if err != nil {
				return err
			}
			// defer fileWriter.Close()

			sumfile, err := os.Open(sumfilename)
			if err != nil {
				return err
			}
			defer sumfile.Close()

			if _, err = io.Copy(fileWriter, sumfile); err != nil {
				return err
			}
		}
		return nil
	})
}

func deploy(client *http.Client, u string, dataFn, sumFn func(*multipart.Writer) error) error {
	if client == nil {
		client = GetDefaultHttpClient()
	}

	pr, pw := io.Pipe()
	request, err := http.NewRequest(http.MethodPost, u, pr)
	if err != nil {
		return err
	}
	mw := multipart.NewWriter(pw)
	request.Header.Set("Content-Type", "multipart/form-data; boundary="+mw.Boundary())

	go func() {
		err := writeRequestBody(mw, dataFn, sumFn)
		if err != nil {
			pw.CloseWithError(err)
		} else {
			pw.Close()
		}
	}()

	response, err := client.Do(request)
	if err != nil {
		pr.CloseWithError(err)
		return err
	} else {
		pr.Close()
	}

	if response.Body != nil {
		defer func(rc io.ReadCloser) {
			io.CopyN(ioutil.Discard, rc, 1<<30)
			rc.Close()
		}(response.Body)
	}

	if response.StatusCode != http.StatusOK {
		if response.Body != nil {
			bs, _ := io.ReadAll(response.Body)
			if len(bs) > 0 {
				return errors.New(string(bs))
			}
		}
		return errors.New(response.Status)
	}
	return nil
}

func writeFile(mw *multipart.Writer, filename string) error {
	fieldValue := filepath.Base(filename)
	fileWriter, err := mw.CreateFormFile(fieldValue, fieldValue)
	if err != nil {
		return err
	}

	//打开文件句柄操作
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := io.Copy(fileWriter, file); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return nil
}

func writeFromReader(mw *multipart.Writer, filename string, reader io.Reader) error {
	fieldValue := filepath.Base(filename)
	fileWriter, err := mw.CreateFormFile(fieldValue, fieldValue)
	if err != nil {
		return err
	}

	if _, err := io.Copy(fileWriter, reader); err != nil {
		return err
	}
	return nil
}

func writeRequestBody(mw *multipart.Writer, dataFn, sumFn func(*multipart.Writer) error) error {
	if err := dataFn(mw); err != nil {
		return err
	}

	if err := sumFn(mw); err != nil {
		return err
	}

	if err := mw.Close(); err != nil {
		return err
	}
	return nil
}

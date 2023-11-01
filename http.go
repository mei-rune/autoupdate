package autoupdate

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"golang.org/x/mod/semver"
)

func GetDefaultSignMethod() string {
	return jwt.SigningMethodPS512.Alg()
}

func LoadPublicKey(keyFile string) (crypto.PublicKey, error) {
	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, jwt.ErrKeyMustBePEMEncoded
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				parsedKey = cert.PublicKey
			} else {
				return nil, err
			}
		}
	}
	return parsedKey, nil
}

func LoadPrivateKey(keyFile string) (crypto.PrivateKey, error) {
	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, jwt.ErrKeyMustBePEMEncoded
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			if parsedKey, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
				return nil, err
			}
		}
	}
	return parsedKey, nil
}

func NewHTTPServer(osdir string, signMethod, privateKey string) (*HTTPServer, error) {
	if signMethod == "" {
		signMethod = GetDefaultSignMethod()
	}
	hs := &HTTPServer{
		dir:           os.DirFS(osdir),
		osdir:         osdir,
		hasher:        defaultHasher,
		signingMethod: jwt.GetSigningMethod(signMethod),
	}

	if privateKey != "" {
		key, err := LoadPrivateKey(privateKey)
		if err != nil {
			return nil, errors.New("Unable to parse RSA private key: " + err.Error())
		}
		hs.privateKey = key
	}

	return hs, nil
}

type HTTPServer struct {
	dir    fs.FS
	osdir  string
	hasher Hasher

	dirCacheLock sync.Mutex
	dirCache     map[string]*dirCache

	privateKey    crypto.PrivateKey
	signingMethod jwt.SigningMethod
}

func (hs *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r.Body != nil {
			io.Copy(ioutil.Discard, r.Body)
			r.Body.Close()
		}
	}()
	if r.Method == http.MethodGet {
		dir := strings.Trim(r.URL.Path, "/")
		if dir == "" {
			http.Error(w, "您必须指定一个仓库!", http.StatusBadRequest)
			return
		}
		st, err := fs.Stat(hs.dir, dir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if st.IsDir() {
			hs.handleDir(w, r, st)
			return
		}
		hs.handleFile(w, r, st)
		return
	}

	if r.Method == http.MethodPost {
		contentType := r.Header.Get("Content-Type")
		if strings.Contains(contentType, "multipart/form-data") {
			hs.handleDeploy(w, r)
			return
		}
		http.Error(w, "没有附件作为参数", http.StatusBadRequest)
		return
	}

	http.NotFound(w, r)
}

const (
	defaultMaxMemory = 32 << 20 // 32 MB
)

func copyReaderToFile(reader io.Reader, filename string) error {
	out, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, reader)
	return err
}

func (hs *HTTPServer) handleDeploy(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(defaultMaxMemory)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	pa := strings.Trim(r.URL.Path, "/")
	if pa == "" {
		http.Error(w, "部署路径不正确: 格式一般为 repo/version", http.StatusBadRequest)
		return
	}
	idx := strings.LastIndexByte(pa, '/')
	if idx <= 0 {
		http.Error(w, "部署路径不正确: 格式一般为 repo/version", http.StatusBadRequest)
		return
	}
	// repo := pa[:idx]
	version := pa[idx+1:]

	if !semver.IsValid(version) {
		http.Error(w, "版本号不正确", http.StatusBadRequest)
		return
	}

	var datafilename string
	var datafile multipart.File
	var sumfile multipart.File

	defer func() {
		if datafile != nil {
			datafile.Close()
		}
		if sumfile != nil {
			sumfile.Close()
		}
	}()

	for _, files := range r.MultipartForm.File {
		if len(files) == 0 {
			continue
		}
		file := files[0]

		ext := filepath.Ext(file.Filename)
		switch strings.ToLower(ext) {
		case ".zip", ".gz":
			if datafilename != "" {
				http.Error(w, "找到多个补丁附件，一次只能上传一个补丁包！", http.StatusBadRequest)
				return
			}
			var err error
			datafile, err = file.Open()
			if err != nil {
				http.Error(w, "读附件 '"+file.Filename+"' 失败: "+err.Error(), http.StatusBadRequest)
				return
			}
			datafilename = filepath.Base(file.Filename)
		case ".sum":
			if sumfile != nil {
				http.Error(w, "找到多个补丁校验文件，一次只能上传一个补丁包和一个校验文件！", http.StatusBadRequest)
				return
			}

			var err error
			sumfile, err = file.Open()
			if err != nil {
				http.Error(w, "读附件 '"+file.Filename+"' 失败: "+err.Error(), http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, "附件 '"+file.Filename+"' 的格式 '"+strings.ToLower(ext)+"' 不支持", http.StatusBadRequest)
			return
		}
	}

	if datafilename == "" {
		http.Error(w, "您是不是没有附件！", http.StatusBadRequest)
		return
	}

	if err := os.MkdirAll(filepath.Join(hs.osdir, pa), 0777); err != nil {
		http.Error(w, "创建目录失败:"+err.Error(), http.StatusBadRequest)
		return
	}

	sumfilename := filepath.Join(hs.osdir, pa, datafilename) + ".sum"
	pkgfilename := filepath.Join(hs.osdir, pa, datafilename)
	tmpfilename := pkgfilename + ".tmp"
	if err = copyReaderToFile(datafile, tmpfilename); err != nil {
		http.Error(w, "保存补丁文件失败:"+err.Error(), http.StatusBadRequest)
		return
	}

	var sum string
	if sumfile != nil {
		bs, err := ioutil.ReadAll(sumfile)
		if err != nil {
			http.Error(w, "读补丁 sum 文件失败:"+err.Error(), http.StatusBadRequest)
			return
		}
		sum = string(bs)

		ok, err := VerifyFile(hs.hasher, tmpfilename, sum)
		if err != nil {
			http.Error(w, "验证补丁完整性失败:"+err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "验证补丁完整性失败，是不是签名方式不一致?", http.StatusBadRequest)
			return
		}
	} else {
		sum = r.FormValue("sum")
		if sum != "" {
			ok, err := VerifyFile(hs.hasher, tmpfilename, sum)
			if err != nil {
				http.Error(w, "验证补丁完整性失败:"+err.Error(), http.StatusInternalServerError)
				return
			}
			if !ok {
				http.Error(w, "验证补丁完整性失败，是不是签名方式不一致?", http.StatusBadRequest)
				return
			}
		} else {
			sum, err = SumFile(hs.hasher, tmpfilename)
			if err != nil {
				http.Error(w, "验证补丁完整性失败:"+err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}

	if err = os.WriteFile(sumfilename, []byte(sum), 0666); err != nil {
		http.Error(w, "保存补丁 sum 文件失败:"+err.Error(), http.StatusBadRequest)
		return
	}

	if err = os.Rename(tmpfilename, pkgfilename); err != nil {
		http.Error(w, "保存补丁 sum 文件失败:"+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "上传成功!")
}

type dirCache struct {
	Time int64
	body []byte
	sign string
}

func (c *dirCache) noTimeout() bool {
	return (time.Now().Unix() - c.Time) < 600
}

const xsignKey = "X-Hw-Sign"

func (hs *HTTPServer) handleDir(w http.ResponseWriter, r *http.Request, st fs.FileInfo) {
	pa := strings.Trim(r.URL.Path, "/")
	if !strings.Contains(pa, "/") {
		http.Error(w, "仓库名不正确，仓库名一般格式为 '仓库名/分支'", http.StatusBadRequest)
		return
	}

	cachedValue := func() *dirCache {
		hs.dirCacheLock.Lock()
		defer hs.dirCacheLock.Unlock()
		if hs.dirCache == nil {
			return nil
		}
		return hs.dirCache[pa]
	}()
	if cachedValue != nil && cachedValue.noTimeout() {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set(xsignKey, cachedValue.sign)
		bs := cachedValue.body
		for len(bs) > 0 {
			n, err := w.Write(bs)
			if err != nil {
				return
			}
			bs = bs[n:]
		}
		return
	}

	handleFunc := func(pa string, value interface{}) error {
		hs.dirCacheLock.Lock()
		defer hs.dirCacheLock.Unlock()
		if hs.dirCache == nil {
			hs.dirCache = map[string]*dirCache{}
		} else {
			cachedValue := hs.dirCache[pa]
			if cachedValue != nil && cachedValue.noTimeout() {
				rendererBody(w, cachedValue.body, cachedValue.sign)
				return nil
			}
		}

		body, sign, err := hs.signBody(value)
		if err != nil {
			return err
		}

		rendererBody(w, body, sign)

		hs.dirCache[pa] = &dirCache{
			Time: time.Now().Unix(),
			body: body,
			sign: sign,
		}
		return nil
	}

	err := ReadRepo(hs.dir, pa, func(list []AvailableUpdate) error {
		return handleFunc(pa, list)
	}, func(pkgs []PackageInfo) error {
		return handleFunc(pa, pkgs)
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (hs *HTTPServer) signBody(list interface{}) ([]byte, string, error) {
	var buf = bytes.NewBuffer(make([]byte, 0, 4*1024))
	err := json.NewEncoder(buf).Encode(list)
	if err != nil {
		return nil, "", err
	}

	sig, err := hs.signingMethod.Sign(buf.String(), hs.privateKey)
	if err != nil {
		return nil, "", err
	}
	return buf.Bytes(), sig, nil
}

func rendererBody(w http.ResponseWriter, body []byte, sig string) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set(xsignKey, sig)
	w.WriteHeader(http.StatusOK)
	for len(body) > 0 {
		n, err := w.Write(body)
		if err != nil {
			return err
		}
		body = body[n:]
	}
	return nil
}

var errMissingSeek = errors.New("fs.File missing Seek method")

func (hs *HTTPServer) handleFile(w http.ResponseWriter, r *http.Request, st fs.FileInfo) {
	in, err := hs.dir.Open(strings.Trim(r.URL.Path, "/"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer in.Close()

	rs, ok := in.(io.ReadSeeker)
	if !ok {
		http.Error(w, errMissingSeek.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, st.Name(), st.ModTime(), rs)
}

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

func (c *HTTPClient) Read(ctx context.Context, repo string) ([]AvailableUpdate, error) {
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}

	response, err := client.Get(c.BaseURL.JoinPath(repo).String())
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
		client = http.DefaultClient
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
		client = http.DefaultClient
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

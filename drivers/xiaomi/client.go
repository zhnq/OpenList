package xiaomi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	anet "github.com/OpenListTeam/OpenList/v4/internal/net"
)

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0.0.0 Safari/537.36"

var errVerification = errors.New("Xiaomi requires phone verification: enable Send SMS and save, then enter the code and save again")

type savedCookie struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Domain  string `json:"domain"`
	Path    string `json:"path"`
	Expires int64  `json:"expires,omitempty"`
}

type session struct {
	Account         string        `json:"account"`
	Cookies         []savedCookie `json:"cookies"`
	Pending         string        `json:"pending_verification,omitempty"`
	Flag            string        `json:"verification_flag,omitempty"`
	PasswordAttempt int64         `json:"password_attempt,omitempty"`
}

type cloudClient struct {
	mu                                            sync.Mutex
	http                                          *http.Client
	signedHTTP                                    *http.Client
	accountBase, cloudBase                        string
	username, passwordHash, deviceID, fingerprint string
	state                                         session
	lastRefresh                                   time.Time
	persist                                       func(session)
}

func newClient(add Addition, persist func(session)) (*cloudClient, error) {
	jar, _ := cookiejar.New(nil)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if conf.Conf != nil {
		anet.SetProxyIfConfigured(transport)
	}
	c := &cloudClient{accountBase: "https://account.xiaomi.com", cloudBase: "https://i.mi.com",
		username: add.Username, passwordHash: add.PasswordHash, deviceID: add.DeviceID,
		fingerprint: add.DeviceFingerprint, persist: persist}
	c.http = &http.Client{Jar: jar, Transport: transport, Timeout: 90 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	c.signedHTTP = &http.Client{Transport: transport, Timeout: 90 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 || !validDownloadURL(req.URL.String()) {
				return errors.New("unexpected Xiaomi download redirect")
			}
			return nil
		}}
	if add.Session != "" {
		if err := json.Unmarshal([]byte(add.Session), &c.state); err != nil {
			return nil, errors.New("invalid saved Xiaomi session")
		}
	}
	if c.state.Account != "" && c.state.Account != add.Username {
		c.state = session{}
		c.passwordHash = ""
	}
	c.state.Account = add.Username
	if c.deviceID == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		c.deviceID = "wb_" + hex.EncodeToString(b)
	}
	if c.fingerprint == "" {
		sum := md5.Sum([]byte(c.deviceID))
		c.fingerprint = hex.EncodeToString(sum[:])
	}
	if add.Password != "" {
		sum := md5.Sum([]byte(add.Password))
		c.passwordHash = strings.ToUpper(hex.EncodeToString(sum[:]))
		// A deliberately entered password must be checked, even if the old
		// account cookies are still valid. Keep the device trust credentials.
		cookies := c.state.Cookies[:0]
		for _, cookie := range c.state.Cookies {
			if cookie.Name != "passToken" && cookie.Name != "serviceToken" {
				cookies = append(cookies, cookie)
			}
		}
		c.state.Cookies = cookies
		c.state.PasswordAttempt = 0
	}
	if c.username == "" || c.passwordHash == "" {
		return nil, errors.New("Xiaomi username and password are required for initial login")
	}
	for _, item := range c.state.Cookies {
		if item.Expires > 0 && item.Expires <= time.Now().Unix() {
			continue
		}
		host := strings.TrimPrefix(item.Domain, ".")
		if host != "account.xiaomi.com" && host != "xiaomi.com" && host != "i.mi.com" && host != "mi.com" {
			continue
		}
		u, _ := url.Parse("https://" + host + "/")
		cookie := &http.Cookie{Name: item.Name, Value: item.Value, Domain: item.Domain, Path: item.Path}
		if item.Expires > 0 {
			cookie.Expires = time.Unix(item.Expires, 0)
		}
		jar.SetCookies(u, []*http.Cookie{cookie})
	}
	u, _ := url.Parse(c.accountBase)
	jar.SetCookies(u, []*http.Cookie{{Name: "deviceId", Value: c.deviceID, Path: "/"}})
	c.remember(u, []*http.Cookie{{Name: "deviceId", Value: c.deviceID, Path: "/"}})
	return c, nil
}

func (c *cloudClient) remember(origin *url.URL, cookies []*http.Cookie) {
	for _, cookie := range cookies {
		domain := strings.TrimPrefix(cookie.Domain, ".")
		if domain == "" {
			domain = origin.Hostname()
		}
		path := cookie.Path
		if path == "" {
			path = "/"
		}
		out := c.state.Cookies[:0]
		for _, old := range c.state.Cookies {
			if strings.TrimPrefix(old.Domain, ".") != domain || old.Path != path || old.Name != cookie.Name {
				out = append(out, old)
			}
		}
		c.state.Cookies = out
		if cookie.MaxAge < 0 || !cookie.Expires.IsZero() && cookie.Expires.Before(time.Now()) {
			continue
		}
		expires := int64(0)
		if !cookie.Expires.IsZero() {
			expires = cookie.Expires.Unix()
		}
		if cookie.MaxAge > 0 {
			expires = time.Now().Unix() + int64(cookie.MaxAge)
		}
		c.state.Cookies = append(c.state.Cookies, savedCookie{cookie.Name, cookie.Value, domain, path, expires})
	}
}

func (c *cloudClient) save() {
	if c.persist != nil {
		c.persist(c.state)
	}
}
func (c *cloudClient) hasToken() bool {
	u, _ := url.Parse(c.cloudBase)
	for _, cookie := range c.http.Jar.Cookies(u) {
		if cookie.Name == "serviceToken" && cookie.Value != "" {
			return true
		}
	}
	return false
}

func sameOrigin(a, b string) bool {
	x, e := url.Parse(a)
	y, f := url.Parse(b)
	return e == nil && f == nil && x.Scheme == y.Scheme && x.Host == y.Host
}

func (c *cloudClient) request(ctx context.Context, target string, form url.Values, headers http.Header, auth bool) (*http.Response, error) {
	if auth && !sameOrigin(target, c.accountBase) && !sameOrigin(target, c.cloudBase) {
		return nil, errors.New("unexpected Xiaomi authentication host")
	}
	method := http.MethodGet
	var body io.Reader
	if form != nil {
		method = http.MethodPost
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, errors.New("invalid Xiaomi request")
	}
	req.Header.Set("User-Agent", userAgent)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	}
	if auth {
		req.Header.Set("Referer", c.cloudBase+"/record")
	}
	for key, values := range headers {
		req.Header[key] = values
	}
	client := c.signedHTTP
	if auth {
		client = c.http
	}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("Xiaomi connection failed")
	}
	if auth {
		c.remember(req.URL, resp.Cookies())
	}
	return resp, nil
}

type apiResponse struct {
	Code            int             `json:"code"`
	Data            json.RawMessage `json:"data"`
	Location        string          `json:"location"`
	NotificationURL string          `json:"notificationUrl"`
	Sign            string          `json:"_sign"`
	QS              string          `json:"qs"`
	Callback        string          `json:"callback"`
	SID             string          `json:"sid"`
	ServiceParam    string          `json:"serviceParam"`
	Flag            int             `json:"flag"`
}

type statusError int

func (e statusError) Error() string { return fmt.Sprintf("Xiaomi HTTP status %d", int(e)) }

func readJSON(resp *http.Response, out any) error {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return statusError(resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return errors.New("failed to read Xiaomi response")
	}
	data = bytes.TrimSpace(bytes.TrimPrefix(data, []byte("&&&START&&&")))
	if len(data) > 0 && data[0] != '{' && data[0] != '[' {
		start := bytes.IndexByte(data, '(')
		end := bytes.LastIndexByte(data, ')')
		if start < 0 || end <= start {
			return errors.New("invalid Xiaomi JSON response")
		}
		data = data[start+1 : end]
	}
	if err = json.Unmarshal(data, out); err != nil {
		return errors.New("invalid Xiaomi JSON response")
	}
	return nil
}

func (c *cloudClient) json(ctx context.Context, target string, form url.Values, out any) error {
	resp, err := c.request(ctx, target, form, nil, true)
	if err != nil {
		return err
	}
	return readJSON(resp, out)
}

func (c *cloudClient) entry(ctx context.Context) (string, error) {
	var result apiResponse
	err := c.json(ctx, c.cloudBase+"/api/user/login?"+url.Values{"followUp": {c.cloudBase}, "_locale": {"zh_CN"}}.Encode(), nil, &result)
	if err != nil {
		return "", err
	}
	var data struct {
		LoginURL string `json:"loginUrl"`
	}
	if json.Unmarshal(result.Data, &data) != nil || data.LoginURL == "" {
		return "", errors.New("Xiaomi login entry missing")
	}
	return data.LoginURL, nil
}

func (c *cloudClient) follow(ctx context.Context, target string) error {
	for i := 0; i < 8; i++ {
		u, err := url.Parse(target)
		if err != nil {
			return errors.New("invalid Xiaomi login callback")
		}
		if strings.Contains(u.Path, "/identity/") && u.Path != "/identity/result/check" {
			c.state.Pending = target
			c.save()
			return errVerification
		}
		resp, err := c.request(ctx, target, nil, nil, true)
		if err != nil {
			return err
		}
		location := resp.Header.Get("Location")
		resp.Body.Close()
		if sameOrigin(target, c.cloudBase) && u.Path == "/sts" && resp.StatusCode < 400 && c.hasToken() {
			c.lastRefresh = time.Now()
			c.state.Pending = ""
			c.save()
			return nil
		}
		if location == "" {
			return errors.New("saved Xiaomi login is no longer valid")
		}
		next, err := u.Parse(location)
		if err != nil {
			return errors.New("invalid Xiaomi redirect")
		}
		target = next.String()
	}
	return errors.New("Xiaomi login redirect limit exceeded")
}

func (c *cloudClient) refresh(ctx context.Context, force bool) error {
	if !force && c.hasToken() && time.Since(c.lastRefresh) < 10*time.Minute {
		return nil
	}
	entry, err := c.entry(ctx)
	if err != nil {
		return err
	}
	err = c.follow(ctx, entry)
	if err == nil || errors.Is(err, errVerification) {
		c.save()
		return err
	}
	if time.Now().Unix()-c.state.PasswordAttempt < 900 {
		return err
	}
	c.state.PasswordAttempt = time.Now().Unix()
	c.save()
	return c.login(ctx)
}

func encryptUsername(username string) (string, string, error) {
	const publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYEVrK/4Mahiv0pUJgTybx4J9P5dUT/Y0PuwMbk+gMU+jrZnBiXGv6/hCH1avIhoBcE535F8nJQQN3UavZdFkYidsoXuEnat3+eVTp3FslyhRwIBDF09v4vDhRtxFOT+R7uH7h/mzmyA2/+lfIMWGIrffXprYizbV76+YQKhoqFQIDAQAB"
	// Match the browser's 16-byte printable AES key and PKCS#7/CBC envelope.
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return "", "", err
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
	for i := range key {
		key[i] = alphabet[int(key[i])%len(alphabet)]
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}
	plain := []byte(username)
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	plain = append(plain, bytes.Repeat([]byte{byte(padding)}, padding)...)
	enc := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, []byte("0102030405060708")).CryptBlocks(enc, plain)
	der, _ := base64.StdEncoding.DecodeString(publicKey)
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", "", err
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return "", "", errors.New("invalid Xiaomi public key")
	}
	wrapped, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(base64.StdEncoding.EncodeToString(key)))
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(enc), base64.StdEncoding.EncodeToString(wrapped) + "." + base64.StdEncoding.EncodeToString([]byte("user")), nil
}

func (c *cloudClient) login(ctx context.Context) error {
	entry, err := c.entry(ctx)
	if err != nil {
		return err
	}
	u, err := url.Parse(entry)
	if err != nil {
		return errors.New("invalid Xiaomi login entry")
	}
	query := u.Query()
	query.Set("_json", "true")
	u.RawQuery = query.Encode()
	var first apiResponse
	if err = c.json(ctx, u.String(), nil, &first); err != nil {
		return err
	}
	if first.Code == 0 && first.Location != "" {
		return c.follow(ctx, first.Location)
	}
	if first.Sign == "" {
		return errors.New("Xiaomi password login signature missing")
	}
	user, eui, err := encryptUsername(c.username)
	if err != nil {
		return errors.New("Xiaomi account encryption failed")
	}
	form := url.Values{"user": {user}, "hash": {c.passwordHash}, "sid": {"i.mi.com"}, "_sign": {first.Sign}, "qs": {first.QS}, "callback": {first.Callback}, "serviceParam": {first.ServiceParam}, "_json": {"true"}, "cc": {"+86"}, "policyName": {"miaccount"}, "captCode": {""}, "deviceFingerprint": {c.fingerprint}, "needTheme": {"false"}, "showActiveX": {"false"}}
	resp, err := c.request(ctx, c.accountBase+"/pass/serviceLoginAuth2", form, http.Header{"Eui": {eui}, "Origin": {c.accountBase}, "X-Requested-With": {"XMLHttpRequest"}}, true)
	if err != nil {
		return err
	}
	var result apiResponse
	err = readJSON(resp, &result)
	c.save()
	if err != nil {
		return err
	}
	if result.NotificationURL != "" {
		c.state.Pending = result.NotificationURL
		c.save()
		return errVerification
	}
	if result.Code != 0 {
		return fmt.Errorf("Xiaomi password login code %d (captcha or user action may be required)", result.Code)
	}
	if result.Location == "" {
		return errors.New("Xiaomi login callback missing")
	}
	return c.follow(ctx, result.Location)
}

func (c *cloudClient) api(ctx context.Context, path string, query url.Values, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.refresh(ctx, false); err != nil {
		return err
	}
	for attempt := 0; attempt < 2; attempt++ {
		var result apiResponse
		err := c.json(ctx, c.cloudBase+path+"?"+query.Encode(), nil, &result)
		if attempt == 0 && (errors.Is(err, statusError(401)) || err == nil && result.Code != 0) {
			if err = c.refresh(ctx, true); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if result.Code != 0 {
			return fmt.Errorf("Xiaomi API code %d", result.Code)
		}
		if err = json.Unmarshal(result.Data, out); err != nil {
			return errors.New("invalid Xiaomi API data")
		}
		return nil
	}
	return errors.New("Xiaomi authentication retry exhausted")
}

func (c *cloudClient) verify(ctx context.Context, send bool, code string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state.Pending == "" {
		return errors.New("no Xiaomi phone verification is pending")
	}
	u, err := url.Parse(c.state.Pending)
	if err != nil {
		return errVerification
	}
	if send {
		q := u.Query()
		q.Set("sid", "i.mi.com")
		q.Set("supportedMask", "0")
		q.Set("_locale", "zh_CN")
		var list apiResponse
		if err = c.json(ctx, c.accountBase+"/identity/list?"+q.Encode(), nil, &list); err != nil {
			return err
		}
		if list.Flag != 4 {
			return errors.New("Xiaomi requires a verification method other than SMS")
		}
		c.state.Flag = strconv.Itoa(list.Flag)
		var prepared apiResponse
		if err = c.json(ctx, c.accountBase+"/identity/auth/verifyPhone?"+url.Values{"_flag": {c.state.Flag}, "_json": {"true"}}.Encode(), nil, &prepared); err != nil {
			return err
		}
		if prepared.Code != 0 {
			return fmt.Errorf("Xiaomi phone preparation code %d", prepared.Code)
		}
		var sent apiResponse
		err = c.json(ctx, c.accountBase+"/identity/auth/sendPhoneTicket", url.Values{"_json": {"true"}, "retry": {"0"}, "icode": {""}}, &sent)
		c.save()
		if err != nil {
			return err
		}
		if sent.Code != 0 {
			return fmt.Errorf("Xiaomi SMS request code %d", sent.Code)
		}
		return errors.New("Xiaomi SMS sent; enter the code and save again")
	}
	var verified apiResponse
	err = c.json(ctx, c.accountBase+"/identity/auth/verifyPhone", url.Values{"ticket": {code}, "_json": {"true"}, "trust": {"true"}, "_flag": {c.state.Flag}}, &verified)
	c.save()
	if err != nil {
		return err
	}
	if verified.Code != 0 {
		return fmt.Errorf("Xiaomi verification code %d", verified.Code)
	}
	return c.follow(ctx, verified.Location)
}

func validDownloadURL(target string) bool {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	for _, domain := range []string{"xiaomi.net", "xiaomi.com", "mi.com"} {
		if strings.HasSuffix(u.Hostname(), "."+domain) {
			return true
		}
	}
	return false
}

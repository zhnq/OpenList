package xiaomi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/http_range"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(status int, body string, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}
}

func testClient(t *testing.T, f transportFunc) *cloudClient {
	t.Helper()
	c, err := newClient(Addition{Username: "123456789", Password: "test-password", DeviceID: "wb_test_device", DeviceFingerprint: "test_fingerprint"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.http.Transport = f
	c.signedHTTP.Transport = f
	return c
}

func loginResponse(r *http.Request) *http.Response {
	switch r.URL.Path {
	case "/api/user/login":
		return response(200, `{"code":0,"data":{"loginUrl":"https://account.xiaomi.com/pass/serviceLogin?sid=i.mi.com&callback=https%3A%2F%2Fi.mi.com%2Fsts%3Fsign%3Dfresh"}}`, nil)
	case "/pass/serviceLogin":
		return response(302, "", http.Header{"Location": {"https://i.mi.com/sts?sign=fresh"}})
	case "/sts":
		return response(302, "", http.Header{"Location": {"https://i.mi.com/"}, "Set-Cookie": {"serviceToken=test-service; Path=/; Domain=i.mi.com"}})
	}
	return nil
}

func TestPaginationAndTokenRefresh(t *testing.T) {
	loginCount := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if out := loginResponse(r); out != nil {
			if r.URL.Path == "/sts" {
				loginCount++
			}
			return out, nil
		}
		if r.URL.Path != "/sfs/ns/recorder/dir/0/list" {
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
		if !strings.Contains(r.Header.Get("Cookie"), "serviceToken=test-service") {
			t.Fatal("missing service token")
		}
		var records []map[string]any
		if r.URL.Query().Get("offset") == "0" {
			for i := 1; i <= 500; i++ {
				records = append(records, map[string]any{"id": i, "name": "same.mp3_1_2", "size": 10, "modify_time": 1700000000000})
			}
		} else {
			records = append(records, map[string]any{"id": "501", "name": "same.mp3_1_2", "size": "10", "modify_time": 1700000000000})
		}
		body, _ := json.Marshal(map[string]any{"code": 0, "data": map[string]any{"list": records}})
		return response(200, string(body), nil), nil
	})
	d := &Xiaomi{client: c}
	root, _ := d.GetRoot(context.Background())
	files, err := d.List(context.Background(), root, model.ListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 501 || loginCount != 1 {
		t.Fatalf("files=%d refreshes=%d", len(files), loginCount)
	}
	if files[0].GetName() == files[500].GetName() {
		t.Fatal("duplicate names must remain distinct")
	}
	if files[0].ModTime().Unix() != 1700000000 {
		t.Fatal("milliseconds not converted")
	}
}

func TestAuthenticationFailureRetriesOnce(t *testing.T) {
	for _, mode := range []string{"http401", "api-code", "persistent401"} {
		t.Run(mode, func(t *testing.T) {
			calls, refreshes := 0, 0
			c := testClient(t, func(r *http.Request) (*http.Response, error) {
				if out := loginResponse(r); out != nil {
					if r.URL.Path == "/sts" {
						refreshes++
					}
					return out, nil
				}
				calls++
				if mode == "persistent401" || calls == 1 && mode == "http401" {
					return response(401, "", nil), nil
				}
				if calls == 1 {
					return response(200, `{"code":1}`, nil), nil
				}
				return response(200, `{"code":0,"data":{"list":[]}}`, nil), nil
			})
			d := &Xiaomi{client: c}
			root, _ := d.GetRoot(context.Background())
			_, err := d.List(context.Background(), root, model.ListArgs{})
			if (err != nil) != (mode == "persistent401") {
				t.Fatalf("unexpected result: %v", err)
			}
			if calls != 2 || refreshes != 2 {
				t.Fatalf("API calls=%d refreshes=%d; authentication retry must be bounded", calls, refreshes)
			}
		})
	}
}

func TestPasswordLoginPreservesSignedCallback(t *testing.T) {
	authCalls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/pass/serviceLogin" {
			if r.URL.Query().Get("_json") != "true" || !strings.Contains(r.URL.Query().Get("callback"), "sign=fresh") {
				t.Fatal("login preflight lost signed callback")
			}
			return response(200, `{"code":70016,"_sign":"test-sign","qs":"test-qs","callback":"https://i.mi.com/sts?sign=fresh","serviceParam":"fresh-param"}`, nil), nil
		}
		if r.URL.Path == "/pass/serviceLoginAuth2" {
			authCalls++
			r.ParseForm()
			if r.Form.Get("user") == "123456789" || r.Header.Get("EUI") == "" || r.Form.Get("sid") != "i.mi.com" || r.Form.Get("serviceParam") != "fresh-param" {
				t.Fatal("incorrect password envelope")
			}
			return response(200, `{"code":0,"location":"https://i.mi.com/sts?sign=fresh"}`, http.Header{"Set-Cookie": {"passToken=latest-pass; Domain=account.xiaomi.com; Path=/"}}), nil
		}
		if out := loginResponse(r); out != nil {
			return out, nil
		}
		t.Fatal("unexpected request")
		return nil, nil
	})
	c.mu.Lock()
	err := c.login(context.Background())
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if authCalls != 1 || !c.hasToken() {
		t.Fatal("password login did not obtain service token")
	}
}

func TestVerificationRequiresExplicitSMS(t *testing.T) {
	requests := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		requests++
		return response(302, "", http.Header{"Location": {"https://account.xiaomi.com/fe/service/identity/authStart?context=fake"}}), nil
	})
	if err := c.follow(context.Background(), "https://account.xiaomi.com/pass/serviceLogin"); err != errVerification {
		t.Fatalf("unexpected error %v", err)
	}
	if requests != 1 || c.state.Pending == "" {
		t.Fatal("verification must be persisted without automatically sending SMS")
	}
}

func TestAuthHostIsolation(t *testing.T) {
	c := testClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("must not contact outside host"); return nil, nil })
	if _, err := c.request(context.Background(), "https://attacker.example/", nil, nil, true); err == nil {
		t.Fatal("unexpected host accepted")
	}
	for _, u := range []string{"http://a.xiaomi.net/", "https://xiaomi.net.evil.example/", "https://user:password@a.xiaomi.net/"} {
		if validDownloadURL(u) {
			t.Fatal("invalid download origin accepted")
		}
	}
}

func TestRangePOSTAndFallback(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprint(partial), func(t *testing.T) {
			c := testClient(t, func(r *http.Request) (*http.Response, error) {
				if out := loginResponse(r); out != nil {
					return out, nil
				}
				if strings.Contains(r.URL.Path, "/storage") {
					return response(200, `{"code":0,"data":{"url":"https://a.xiaomi.net/kss_web/rd"}}`, nil), nil
				}
				if r.URL.Path == "/kss_web/rd" {
					if r.Header.Get("Cookie") != "" {
						t.Fatal("credential leaked to signed host")
					}
					return response(200, `callback({"url":"https://a.xiaomi.net/download_file","meta":"fake-meta"});`, nil), nil
				}
				if r.URL.Path == "/download_file" {
					r.ParseForm()
					if r.Method != "POST" || r.Form.Get("meta") != "fake-meta" || r.Header.Get("Range") != "bytes=2-4" || r.Header.Get("Cookie") != "" {
						t.Fatal("incorrect POST range request")
					}
					if partial {
						return response(206, "234", http.Header{"Content-Range": {"bytes 2-4/10"}}), nil
					}
					return response(200, "0123456789", nil), nil
				}
				t.Fatal("unexpected request")
				return nil, nil
			})
			r, err := c.openRange(context.Background(), "123", 10, http_range.Range{Start: 2, Length: 3})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			data, _ := io.ReadAll(r)
			if string(data) != "234" {
				t.Fatalf("bad range %q", data)
			}
		})
	}
}

func TestEncryptedUsernameAndNames(t *testing.T) {
	a, eui, err := encryptUsername("account@example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := encryptUsername("account@example.com")
	enc, _ := base64.StdEncoding.DecodeString(a)
	parts := strings.Split(eui, ".")
	wrapped, _ := base64.StdEncoding.DecodeString(parts[0])
	if a == b || len(enc)%16 != 0 || len(wrapped) != 128 || parts[1] != base64.StdEncoding.EncodeToString([]byte("user")) {
		t.Fatal("incorrect encrypted account envelope")
	}
	name := recordingName("../../demo.mp3_1_2", "123")
	if strings.ContainsAny(name, "/\\") || !strings.HasSuffix(name, "--123.mp3") {
		t.Fatalf("unsafe name %q", name)
	}
	if timestamp(json.Number("1700000000000")).Before(time.Unix(1700000000, 0)) {
		t.Fatal("bad timestamp")
	}
}

func TestSMSVerificationPersistsDeviceTrust(t *testing.T) {
	sent := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/identity/list":
			if r.URL.Query().Get("context") != "test-context" {
				t.Fatal("verification context lost")
			}
			return response(200, `{"code":2,"flag":4}`, nil), nil
		case "/identity/auth/sendPhoneTicket":
			sent++
			return response(200, `{"code":0}`, nil), nil
		case "/identity/auth/verifyPhone":
			if r.Method == http.MethodGet {
				return response(200, `{"code":0}`, nil), nil
			}
			r.ParseForm()
			if r.Form.Get("trust") != "true" || r.Form.Get("ticket") != "123456" || r.Form.Get("_flag") != "4" {
				t.Fatal("incorrect trusted-device verification")
			}
			return response(200, `{"code":0,"location":"https://account.xiaomi.com/identity/result/check"}`, http.Header{"Set-Cookie": {"pass_ptd=test-trust; Path=/; Domain=account.xiaomi.com; Max-Age=33696000"}}), nil
		case "/identity/result/check":
			return response(302, "", http.Header{"Location": {"https://account.xiaomi.com/pass/serviceLogin/end"}}), nil
		case "/pass/serviceLogin/end":
			return response(302, "", http.Header{"Location": {"https://i.mi.com/sts"}, "Set-Cookie": {"passToken=verified-pass; Path=/; Domain=account.xiaomi.com"}}), nil
		}
		if out := loginResponse(r); out != nil {
			return out, nil
		}
		t.Fatal("unexpected verification request")
		return nil, nil
	})
	c.state.Pending = "https://account.xiaomi.com/fe/service/identity/authStart?context=test-context"
	if err := c.verify(context.Background(), true, ""); err == nil || !strings.Contains(err.Error(), "SMS sent") {
		t.Fatal("missing sent-code prompt")
	}
	if sent != 1 {
		t.Fatal("SMS was sent more than once")
	}
	if err := c.verify(context.Background(), false, "123456"); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, cookie := range c.state.Cookies {
		if cookie.Name == "pass_ptd" && cookie.Expires > time.Now().Unix() {
			found = true
		}
	}
	if !found || c.state.Pending != "" || !c.hasToken() {
		t.Fatal("verified login state was not retained")
	}
}

func TestChangingAccountCannotReusePasswordHash(t *testing.T) {
	data, _ := json.Marshal(session{Account: "old-account"})
	if _, err := newClient(Addition{Username: "new-account", PasswordHash: "old-hash", Session: string(data)}, nil); err == nil {
		t.Fatal("old account credential reused for new account")
	}
}

func TestReadOnlyDriver(t *testing.T) {
	d := &Xiaomi{}
	if !d.Config().OnlyProxy || !d.Config().NoUpload {
		t.Fatal("read-only proxy configuration missing")
	}
	if _, ok := any(d).(interface {
		Remove(context.Context, model.Obj) error
	}); ok {
		t.Fatal("recording deletion must not be implemented")
	}
}

package xiaomi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/OpenListTeam/OpenList/v4/pkg/http_range"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
)

type Xiaomi struct {
	model.Storage
	Addition
	client *cloudClient
}

func (d *Xiaomi) Config() driver.Config          { return config }
func (d *Xiaomi) GetAddition() driver.Additional { return &d.Addition }

func (d *Xiaomi) Init(ctx context.Context) error {
	passwordEntered := d.Password != ""
	c, err := newClient(d.Addition, func(state session) {
		data, err := json.Marshal(state)
		if err == nil {
			d.Session = string(data)
			for _, cookie := range state.Cookies {
				if cookie.Name == "deviceId" && strings.TrimPrefix(cookie.Domain, ".") == "account.xiaomi.com" {
					d.DeviceID = cookie.Value
				}
			}
			if d.Storage.ID != 0 {
				op.MustSaveDriverStorage(d)
			}
		}
	})
	if err != nil {
		return err
	}
	d.client = c
	d.DeviceID = c.deviceID
	d.DeviceFingerprint = c.fingerprint
	d.PasswordHash = c.passwordHash
	// Retain the credential-equivalent hash, not an additional plaintext password.
	d.Password = ""
	send, code := d.SendSMS, d.SMSCode
	d.SendSMS = false
	d.SMSCode = ""
	if send || code != "" {
		err = c.verify(ctx, send, code)
	} else {
		c.mu.Lock()
		if passwordEntered {
			err = c.login(ctx)
		} else {
			err = c.refresh(ctx, true)
		}
		c.mu.Unlock()
	}
	c.save()
	return err
}

func (d *Xiaomi) Drop(context.Context) error {
	if d.client != nil {
		d.client.http.CloseIdleConnections()
		d.client.signedHTTP.CloseIdleConnections()
	}
	return nil
}

func (d *Xiaomi) GetRoot(context.Context) (model.Obj, error) {
	return &model.Object{ID: "0", Name: "Recordings", IsFolder: true}, nil
}

type recording struct {
	ID       json.Number `json:"id"`
	Name     string      `json:"name"`
	Size     json.Number `json:"size"`
	Modified json.Number `json:"modify_time"`
	Created  json.Number `json:"create_time"`
	SHA1     string      `json:"sha1"`
}

var extension = regexp.MustCompile(`(?i)\.(mp3|aac|m4a|amr|wav)(?:_|$)`)
var unsafeName = regexp.MustCompile(`[\\/:*?"<>|\x00-\x1f]`)

func recordingName(raw, id string) string {
	match := extension.FindStringSubmatchIndex(raw)
	if len(match) > 0 {
		raw = raw[:match[3]]
	}
	raw = strings.Trim(unsafeName.ReplaceAllString(raw, "_"), ". ")
	if raw == "" {
		raw = "recording"
	}
	ext := path.Ext(raw)
	if len(match) == 0 {
		ext = ".bin"
	}
	stem := strings.TrimSuffix(raw, ext)
	if len(stem) > 145 {
		stem = stem[:145]
		for !utf8.ValidString(stem) {
			stem = stem[:len(stem)-1]
		}
	}
	return stem + "--" + id + ext
}

func timestamp(number json.Number) time.Time {
	value, _ := number.Int64()
	if value > 1e11 {
		return time.UnixMilli(value)
	}
	return time.Unix(value, 0)
}

func (d *Xiaomi) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	if dir.GetID() != "0" {
		return nil, errs.ObjectNotFound
	}
	var files []model.Obj
	seen := map[string]bool{}
	for offset := 0; offset < 1000000; offset += 500 {
		var page struct {
			List []recording `json:"list"`
		}
		err := d.client.api(ctx, "/sfs/ns/recorder/dir/0/list", url.Values{"limit": {"500"}, "offset": {strconv.Itoa(offset)}, "ts": {strconv.FormatInt(time.Now().UnixMilli(), 10)}}, &page)
		if err != nil {
			return nil, err
		}
		added := 0
		for _, item := range page.List {
			id := item.ID.String()
			if id == "" {
				return nil, errors.New("Xiaomi recording ID missing")
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			added++
			size, err := item.Size.Int64()
			if err != nil || size < 0 {
				return nil, errors.New("invalid Xiaomi recording size")
			}
			files = append(files, &model.Object{ID: id, Name: recordingName(item.Name, id), Size: size, Modified: timestamp(item.Modified), Ctime: timestamp(item.Created), HashInfo: utils.NewHashInfo(utils.SHA1, item.SHA1)})
		}
		if len(page.List) < 500 {
			return files, nil
		}
		if added == 0 {
			return nil, errors.New("Xiaomi pagination stopped advancing")
		}
	}
	return nil, errors.New("Xiaomi pagination exceeded limit")
}

func (d *Xiaomi) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	if file.IsDir() {
		return nil, errs.NotFile
	}
	expires := time.Minute
	return &model.Link{Expiration: &expires, RangeReader: stream.RangeReaderFunc(func(ctx context.Context, r http_range.Range) (io.ReadCloser, error) {
		return d.client.openRange(ctx, file.GetID(), file.GetSize(), r)
	})}, nil
}

func (c *cloudClient) openRange(ctx context.Context, id string, size int64, r http_range.Range) (io.ReadCloser, error) {
	if r.Start < 0 || r.Start > size || r.Length < -1 {
		return nil, http_range.ErrInvalid
	}
	if r.Length < 0 || r.Length > size-r.Start {
		r.Length = size - r.Start
	}
	if r.Length == 0 {
		return io.NopCloser(strings.NewReader("")), nil
	}
	stamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	var storage struct {
		URL string `json:"url"`
	}
	if err := c.api(ctx, "/sfs/ns/recorder/file/"+url.PathEscape(id)+"/cb/dl_sfs_cb_"+stamp+"_0/storage", url.Values{"ts": {stamp}}, &storage); err != nil {
		return nil, err
	}
	if !validDownloadURL(storage.URL) {
		return nil, errors.New("unexpected Xiaomi storage host")
	}
	resp, err := c.request(ctx, storage.URL, nil, nil, false)
	if err != nil {
		return nil, err
	}
	var signed struct {
		URL  string `json:"url"`
		Meta string `json:"meta"`
	}
	if err = readJSON(resp, &signed); err != nil {
		return nil, err
	}
	if !validDownloadURL(signed.URL) || signed.Meta == "" {
		return nil, errors.New("invalid Xiaomi signed download")
	}
	resp, err = c.request(ctx, signed.URL, url.Values{"meta": {signed.Meta}}, http_range.ApplyRangeToHttpHeader(r, nil), false)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		resp.Body.Close()
		return nil, statusError(resp.StatusCode)
	}
	if resp.StatusCode == http.StatusPartialContent {
		start, end, err := http_range.ParseContentRange(resp.Header.Get("Content-Range"))
		if err != nil || start != r.Start || end-start+1 != r.Length {
			resp.Body.Close()
			return nil, errors.New("Xiaomi download range mismatch")
		}
	} else if r.Start > 0 {
		// Some KSS endpoints ignore Range on POST. Discard the prefix instead of
		// returning incorrect bytes; never depend on a separate proxy process.
		if _, err = io.CopyN(io.Discard, resp.Body, r.Start); err != nil {
			resp.Body.Close()
			return nil, errors.New("Xiaomi download ended before requested offset")
		}
	}
	return &limitedBody{Reader: io.LimitReader(resp.Body, r.Length), body: resp.Body}, nil
}

type limitedBody struct {
	io.Reader
	body io.ReadCloser
}

func (b *limitedBody) Close() error { return b.body.Close() }

var _ driver.Driver = (*Xiaomi)(nil)
var _ driver.GetRooter = (*Xiaomi)(nil)

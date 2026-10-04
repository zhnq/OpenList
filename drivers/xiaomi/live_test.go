package xiaomi

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/http_range"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
)

// Opt-in live test: never embed credentials or a real recording in this package.
func TestLiveCloud(t *testing.T) {
	file := os.Getenv("XIAOMI_TEST_ADDITION")
	if file == "" {
		t.Skip("set XIAOMI_TEST_ADDITION to a private addition JSON file")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal("cannot read private live-test configuration")
	}
	var add Addition
	if json.Unmarshal(data, &add) != nil {
		t.Fatal("invalid private live-test configuration")
	}
	d := &Xiaomi{Addition: add}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err = d.Init(ctx); err != nil {
		t.Fatal(err)
	}
	root, _ := d.GetRoot(ctx)
	items, err := d.List(ctx, root, model.ListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 {
		t.Fatal("no recordings available for live validation")
	}
	t.Logf("live recordings: %d", len(items))
	var small model.Obj
	for _, item := range items {
		if item.GetSize() > 32 && (small == nil || item.GetSize() < small.GetSize()) {
			small = item
		}
	}
	if small == nil {
		t.Fatal("no suitable sample recording")
	}
	link, err := d.Link(ctx, small, model.LinkArgs{})
	if err != nil {
		t.Fatal(err)
	}
	body, err := link.RangeReader.RangeRead(ctx, http_range.Range{Length: -1})
	if err != nil {
		t.Fatal(err)
	}
	sample, err := io.ReadAll(body)
	body.Close()
	if err != nil || int64(len(sample)) != small.GetSize() {
		t.Fatal("sample length mismatch")
	}
	sha := sha1.Sum(sample)
	obj := small.(*model.Object)
	if hex.EncodeToString(sha[:]) != obj.HashInfo.GetHash(utils.SHA1) {
		t.Fatal("sample SHA1 mismatch")
	}
	body, err = link.RangeReader.RangeRead(ctx, http_range.Range{Start: 2, Length: 16})
	if err != nil {
		t.Fatal(err)
	}
	part, err := io.ReadAll(body)
	body.Close()
	if err != nil || string(part) != string(sample[2:18]) {
		t.Fatal("live range mismatch")
	}
	t.Log("cloud POST download, SHA1 and range verified")
	// Require a real password exchange instead of letting an existing passToken
	// turn this into a refresh-only test. Preserve the trusted device cookies.
	u, _ := url.Parse(d.client.accountBase)
	d.client.http.Jar.SetCookies(u, []*http.Cookie{{Name: "passToken", Value: "", Domain: u.Hostname(), Path: "/", MaxAge: -1}})
	d.client.mu.Lock()
	err = d.client.login(ctx)
	d.client.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("fresh encrypted-account password login verified")
	d.client.save()
	updated, _ := json.Marshal(d.Addition)
	if err = os.WriteFile(file, updated, 0600); err != nil {
		t.Fatal("cannot persist live-test state")
	}
}

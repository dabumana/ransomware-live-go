package ransomware

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestWithHTTPClient(t *testing.T) {
	c := NewClient("k")
	hc := &http.Client{}
	WithHTTPClient(hc)(c)
	if c.httpClient != hc {
		t.Fatal("http client not set")
	}
}

func TestWithBaseURL(t *testing.T) {
	c := NewClient("k")
	WithBaseURL(DefaultBaseURL)(c)
	if c.baseURL != DefaultBaseURL {
		t.Fatal("base url not set")
	}
}

func TestNewClient(t *testing.T) {
	c := NewClient("key")
	if c.apiKey != "key" || c.baseURL != DefaultBaseURL || c.httpClient == nil {
		t.Fatal("bad client defaults")
	}
	if c.httpClient.Timeout != DefaultTimeout {
		t.Fatal("bad timeout")
	}
}

func TestDoRequest(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-API-KEY") != "key" || r.Header.Get("Accept") != "application/json" {
				t.Fatal("bad headers")
			}
			if r.URL.Path != "/groups" {
				t.Fatal("bad path")
			}
			_, _ = io.WriteString(w, `[{"group":"lockbit","victims":1}]`)
		}))
		defer ts.Close()

		c := NewClient("key", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
		var out []GroupSummary
		if err := c.doRequest("GET", "groups", nil, &out); err != nil {
			t.Fatal(err)
		}
		if len(out) != 1 || out[0].Group != "lockbit" {
			t.Fatal("bad decode")
		}
	})

	t.Run("query and status error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.RawQuery != "a=b" {
				t.Fatal("bad query")
			}
			http.Error(w, "nope", http.StatusBadRequest)
		}))
		defer ts.Close()

		c := NewClient("key", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
		err := c.doRequest("GET", "x", url.Values{"a": {"b"}}, nil)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("request build error", func(t *testing.T) {
		c := NewClient("key")
		err := c.doRequest("GET", "://bad", nil, nil)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("transport error", func(t *testing.T) {
		c := NewClient("key", WithHTTPClient(&http.Client{
			Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("boom")
			}),
		}))
		err := c.doRequest("GET", "x", nil, nil)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestListGroups(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `[{"group":"lockbit","victims":10}]`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.ListGroups()
	if err != nil || len(out) != 1 || out[0].Group != "lockbit" {
		t.Fatal("bad list groups")
	}
}

func TestGetGroup(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"group":"lockbit","description":"d","victims":1}`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.GetGroup("lockbit")
	if err != nil || out.Group != "lockbit" || out.Description != "d" {
		t.Fatal("bad get group")
	}
}

func TestGetRecentVictims(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("order") != "desc" {
			t.Fatal("bad order")
		}
		_, _ = io.WriteString(w, `[{"victim":"v1","group":"g1"}]`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.GetRecentVictims("desc")
	if err != nil || len(out) != 1 || out[0].Victim != "v1" {
		t.Fatal("bad recent victims")
	}
}

func TestListVictims(t *testing.T) {
	t.Run("missing filter", func(t *testing.T) {
		c := NewClient("k")
		_, err := c.ListVictims(VictimFilter{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("with filter", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("group") != "g1" || r.URL.Query().Get("country") != "us" {
				t.Fatal("bad filters")
			}
			_, _ = io.WriteString(w, `[{"victim":"v1","group":"g1"}]`)
		}))
		defer ts.Close()

		c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
		out, err := c.ListVictims(VictimFilter{Group: "g1", Country: "us"})
		if err != nil || len(out) != 1 || out[0].Victim != "v1" {
			t.Fatal("bad list victims")
		}
	})
}

func TestSearchVictims(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") != "hospital" {
			t.Fatal("bad q")
		}
		_, _ = io.WriteString(w, `[{"victim":"v1","group":"g1"}]`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.SearchVictims("hospital", VictimFilter{Year: "2026"})
	if err != nil || len(out) != 1 || out[0].Victim != "v1" {
		t.Fatal("bad search victims")
	}
}

func TestGetVictim(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"victim":"v1","group":"g1","description":"d"}`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.GetVictim("1")
	if err != nil || out.Victim != "v1" || out.Description != "d" {
		t.Fatal("bad get victim")
	}
}

func TestListIOCGroups(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") != "md5" {
			t.Fatal("bad type")
		}
		_, _ = io.WriteString(w, `[{"group":"g1","types":{"md5":1}}]`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.ListIOCGroups("md5")
	if err != nil || len(out) != 1 || out[0].Group != "g1" {
		t.Fatal("bad ioc groups")
	}
}

func TestGetGroupIOCs(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") != "md5" {
			t.Fatal("bad type")
		}
		_, _ = io.WriteString(w, `{"group":"g1","md5":["a"]}`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.GetGroupIOCs("g1", "md5")
	if err != nil || out.Group != "g1" || len(out.MD5) != 1 {
		t.Fatal("bad group iocs")
	}
}

func TestListNegotiationGroups(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `[{"group":"g1","chats":2}]`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.ListNegotiationGroups()
	if err != nil || len(out) != 1 || out[0].Chats != 2 {
		t.Fatal("bad negotiation groups")
	}
}

func TestListNegotiationChats(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `[{"id":"c1","messages":3}]`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.ListNegotiationChats("g1")
	if err != nil || len(out) != 1 || out[0].ID != "c1" {
		t.Fatal("bad negotiation chats")
	}
}

func TestGetNegotiationChat(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"id":"c1","messages":[{"sender":"a","timestamp":"2026-07-12T00:00:00Z","content":"hi"}]}`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.GetNegotiationChat("g1", "c1")
	if err != nil || out.ID != "c1" || len(out.Messages) != 1 || out.Messages[0].Sender != "a" {
		t.Fatal("bad negotiation chat")
	}
}

func TestListRansomNoteGroups(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `[{"group":"g1","notes":1}]`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.ListRansomNoteGroups()
	if err != nil || len(out) != 1 || out[0].Notes != 1 {
		t.Fatal("bad ransom note groups")
	}
}

func TestListRansomNotes(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `["note1.txt"]`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.ListRansomNotes("g1")
	if err != nil || len(out) != 1 || out[0] != "note1.txt" {
		t.Fatal("bad ransom notes")
	}
}

func TestGetRansomNote(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"extension":".txt","content":"hello"}`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.GetRansomNote("g1", "note1")
	if err != nil || out.Extension != ".txt" || out.Content != "hello" {
		t.Fatal("bad ransom note")
	}
}

func TestListYARAGroups(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `[{"group":"g1","rules":1}]`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.ListYARAGroups()
	if err != nil || len(out) != 1 || out[0].Rules != 1 {
		t.Fatal("bad yara groups")
	}
}

func TestGetYARARules(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `[{"filename":"a.yar","content":"rule a"}]`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.GetYARARules("g1")
	if err != nil || len(out) != 1 || out[0].Filename != "a.yar" {
		t.Fatal("bad yara rules")
	}
}

func TestListPressEntries(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("year") != "2026" || r.URL.Query().Get("country") != "US" {
			t.Fatal("bad query")
		}
		_, _ = io.WriteString(w, `[{"id":"1","title":"t"}]`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.ListPressEntries("2026", "", "US")
	if err != nil || len(out) != 1 || out[0].ID != "1" {
		t.Fatal("bad press entries")
	}
}

func TestGetRecentPressEntries(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("country") != "US" {
			t.Fatal("bad country")
		}
		_, _ = io.WriteString(w, `[{"id":"1","title":"t"}]`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.GetRecentPressEntries("US")
	if err != nil || len(out) != 1 || out[0].ID != "1" {
		t.Fatal("bad recent press entries")
	}
}

func TestGetCSIRTContacts(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `[{"name":"CERT","email":"a@b.com"}]`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.GetCSIRTContacts("US")
	if err != nil || len(out) != 1 || out[0].Name != "CERT" {
		t.Fatal("bad csirt contacts")
	}
}

func TestGetSECFilings(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("ticker") != "AAPL" || q.Get("item105") != "true" || q.Get("item801") != "true" {
			t.Fatal("bad sec query")
		}
		_, _ = io.WriteString(w, `[{"id":"1","ticker":"AAPL"}]`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.GetSECFilings("AAPL", "", "", "", true, true)
	if err != nil || len(out) != 1 || out[0].Ticker != "AAPL" {
		t.Fatal("bad sec filings")
	}
}

func TestListSectors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `[{"sector":"Healthcare","count":1}]`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.ListSectors()
	if err != nil || len(out) != 1 || out[0].Sector != "Healthcare" {
		t.Fatal("bad sectors")
	}
}

func TestGetStats(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"total_victims":1,"total_groups":2,"total_press":3,"last_discovered":"2026-07-12"}`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.GetStats()
	if err != nil || out.TotalVictims != 1 || out.TotalGroups != 2 {
		t.Fatal("bad stats")
	}
}

func TestValidateKey(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"valid":true,"client_id":"abc"}`)
	}))
	defer ts.Close()

	c := NewClient("k", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	out, err := c.ValidateKey()
	if err != nil || !out.Valid || out.ClientID != "abc" {
		t.Fatal("bad validate key")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

var _ = bytes.MinRead
var _ = time.Second

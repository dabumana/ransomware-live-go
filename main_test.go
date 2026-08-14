package ransomware

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	c := NewClient("test-key", WithBaseURL(ts.URL+"/"), WithHTTPClient(ts.Client()))
	return c, ts
}

func TestNewClient(t *testing.T) {
	c := NewClient("key")
	if c.apiKey != "key" || c.baseURL != DefaultBaseURL || c.httpClient == nil {
		t.Fatal("bad client defaults")
	}
	if c.httpClient.Timeout != DefaultTimeout {
		t.Fatal("bad timeout")
	}
	if c.userAgent != DefaultUserAgent {
		t.Fatal("bad user agent")
	}
}

func TestOptions(t *testing.T) {
	c := NewClient("k")
	hc := &http.Client{Timeout: time.Second}
	WithHTTPClient(hc)(c)
	WithBaseURL("https://example.com/")(c)
	WithUserAgent("agent/1")(c)
	if c.httpClient != hc || c.baseURL != "https://example.com/" || c.userAgent != "agent/1" {
		t.Fatal("options not applied")
	}
}

func TestDoRequestHeaders(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-KEY") != "test-key" {
			t.Fatal("bad api key header")
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Fatal("bad accept header")
		}
		if r.Header.Get("User-Agent") == "" {
			t.Fatal("missing user agent")
		}
		_, _ = io.WriteString(w, `[{"group":"lockbit","victims":1}]`)
	})
	defer ts.Close()

	var out []GroupSummary
	if err := c.get(context.Background(), "groups", nil, &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Group != "lockbit" {
		t.Fatal("bad decode")
	}
}

func TestDoRequestErrors(t *testing.T) {
	t.Run("api error mapping", func(t *testing.T) {
		cases := []struct {
			status int
			check  func(*APIError) bool
		}{
			{http.StatusBadRequest, func(e *APIError) bool { return e.IsBadRequest() }},
			{http.StatusUnauthorized, func(e *APIError) bool { return e.IsUnauthorized() }},
			{http.StatusForbidden, func(e *APIError) bool { return e.IsUnauthorized() }},
			{http.StatusNotFound, func(e *APIError) bool { return e.IsNotFound() }},
			{http.StatusTooManyRequests, func(e *APIError) bool { return e.IsRateLimit() }},
		}
		for _, tc := range cases {
			c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "nope", tc.status)
			})
			_, err := c.ListGroups()
			ts.Close()
			apiErr, ok := AsAPIError(err)
			if !ok {
				t.Fatalf("status %d: expected APIError, got %v", tc.status, err)
			}
			if !tc.check(apiErr) {
				t.Fatalf("status %d: Is* check failed for %+v", tc.status, apiErr)
			}
			if apiErr.StatusCode != tc.status || !strings.Contains(apiErr.Error(), "nope") {
				t.Fatalf("status %d: bad APIError payload %+v", tc.status, apiErr)
			}
		}
	})

	t.Run("query encoding", func(t *testing.T) {
		c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.RawQuery != "a=b&c=d%2Be" {
				t.Fatalf("bad query: %s", r.URL.RawQuery)
			}
			_, _ = io.WriteString(w, `{}`)
		})
		defer ts.Close()
		var out map[string]any
		if err := c.get(context.Background(), "x", url.Values{"a": {"b"}, "c": {"d+e"}}, &out); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		c := NewClient("key", WithHTTPClient(&http.Client{
			Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("boom")
			}),
		}))
		if _, err := c.ListGroups(); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("decode error", func(t *testing.T) {
		c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `not json`)
		})
		defer ts.Close()
		var out map[string]any
		if err := c.get(context.Background(), "x", nil, &out); err == nil {
			t.Fatal("expected decode error")
		}
	})

	t.Run("wrapped error", func(t *testing.T) {
		c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusNotFound)
		})
		defer ts.Close()
		_, err := c.GetGroup("missing")
		wrapped := errors.Join(err, errors.New("extra"))
		if !IsAPIError(wrapped) {
			t.Fatal("IsAPIError should unwrap")
		}
		apiErr, ok := AsAPIError(wrapped)
		if !ok || !apiErr.IsNotFound() {
			t.Fatal("AsAPIError should unwrap")
		}
	})
}

func TestListGroups(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/groups" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `[{"group":"lockbit","altname":"LockBit 3.0","victims":10}]`)
	})
	defer ts.Close()

	out, err := c.ListGroups()
	if err != nil || len(out) != 1 || out[0].Group != "lockbit" || out[0].Victims != 10 {
		t.Fatal("bad list groups")
	}
	if out[0].AltName == nil || *out[0].AltName != "LockBit 3.0" {
		t.Fatal("bad altname")
	}
}

func TestGetGroup(t *testing.T) {
	body := `{
		"group":"lockbit",
		"description":"d",
		"victims":1,
		"locations":[{"available":false,"enabled":true,"fqdn":"x.onion","slug":"http://x.onion","title":"t","type":"DLS"}],
		"ttps":[{"tactic_id":"TA0001","tactic_name":"Initial Access","techniques":[{"technique_id":"T1078","technique_name":"Valid Accounts"}]}],
		"vulnerabilities":[{"id":"CVE-2024-1234","cvss":9.1}],
		"tools":["mimikatz"],
		"has_negotiations":true,
		"negotiation_count":2,
		"has_ransomnote":true,
		"ransomnotes_count":3,
		"has_yara":true,
		"yara_count":4,
		"has_iocs":true,
		"iocs_count":5
	}`
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/groups/lockbit" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, body)
	})
	defer ts.Close()

	out, err := c.GetGroup("lockbit")
	if err != nil || out.Group != "lockbit" || out.Description != "d" {
		t.Fatal("bad get group")
	}
	if len(out.Locations) != 1 || out.Locations[0].FQDN != "x.onion" {
		t.Fatal("bad locations")
	}
	if len(out.TTPs) != 1 || out.TTPs[0].TacticName != "Initial Access" || len(out.TTPs[0].Techniques) != 1 {
		t.Fatal("bad ttps")
	}
	if len(out.Vulnerabilities) != 1 || out.Vulnerabilities[0].CVSS != 9.1 {
		t.Fatal("bad vulnerabilities")
	}
	if !out.HasNegotiations || out.NegotiationCount != 2 || !out.HasRansomNote || out.RansomNotesCount != 3 {
		t.Fatal("bad flags")
	}
}

func TestGetGroupFlexibleLists(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{
			"group":"g",
			"locations":["http://a.onion","http://b.onion"],
			"ttps":["T1078","T1133"],
			"vulnerabilities":["CVE-1","CVE-2"],
			"negotiationchats":true,
			"ransomnotes":true,
			"yara":true,
			"iocs":true
		}`)
	})
	defer ts.Close()

	out, err := c.GetGroup("g")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Locations) != 2 || out.Locations[0].Slug != "http://a.onion" {
		t.Fatal("bad string locations")
	}
	if len(out.TTPs) != 2 || out.TTPs[0].TechniqueName != "T1078" {
		t.Fatal("bad string ttps")
	}
	if len(out.Vulnerabilities) != 2 || out.Vulnerabilities[0].ID != "CVE-1" {
		t.Fatal("bad string vulnerabilities")
	}
	if !out.NegotiationChats || !out.RansomNotes || !out.YARA || !out.IOCs {
		t.Fatal("bad legacy flags")
	}
}

func TestGetGroupCompat(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/group/lockbit" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"group":"lockbit"}`)
	})
	defer ts.Close()

	out, err := c.GetGroupCompat("lockbit")
	if err != nil || out.Group != "lockbit" {
		t.Fatal("bad get group compat")
	}
}

func TestGetRecentVictims(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("order") != "attacked" {
			t.Fatal("bad order")
		}
		_, _ = io.WriteString(w, `[{"id":"a","victim":"v1","group":"g1","activity":"Healthcare","website":"v1.com","permalink":"https://x/id/a"}]`)
	})
	defer ts.Close()

	out, err := c.GetRecentVictims("attacked")
	if err != nil || len(out) != 1 || out[0].Victim != "v1" {
		t.Fatal("bad recent victims")
	}
	if out[0].Activity != "Healthcare" || out[0].Sector != "Healthcare" {
		t.Fatal("activity/sector alias failed")
	}
	if out[0].Website != "v1.com" || out[0].Domain != "v1.com" {
		t.Fatal("website/domain alias failed")
	}
	if out[0].Permalink != "https://x/id/a" || out[0].URL != "https://x/id/a" {
		t.Fatal("permalink/url alias failed")
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

	t.Run("year requires month", func(t *testing.T) {
		c := NewClient("k")
		_, err := c.ListVictims(VictimFilter{Year: "2026"})
		if err == nil {
			t.Fatal("expected year/month error")
		}
	})

	t.Run("month requires year", func(t *testing.T) {
		c := NewClient("k")
		_, err := c.ListVictims(VictimFilter{Month: "06"})
		if err == nil {
			t.Fatal("expected month/year error")
		}
	})

	t.Run("with filter", func(t *testing.T) {
		c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/victims/" {
				t.Fatalf("bad path %s", r.URL.Path)
			}
			q := r.URL.Query()
			if q.Get("group") != "g1" || q.Get("country") != "US" ||
				q.Get("year") != "2026" || q.Get("month") != "06" || q.Get("date") != "attacked" {
				t.Fatalf("bad filters: %v", q)
			}
			_, _ = io.WriteString(w, `[{"victim":"v1","group":"g1","activity":"Healthcare"}]`)
		})
		defer ts.Close()

		out, err := c.ListVictims(VictimFilter{
			Group: "g1", Country: "US", Year: "2026", Month: "06", Date: "attacked",
		})
		if err != nil || len(out) != 1 || out[0].Activity != "Healthcare" {
			t.Fatal("bad list victims")
		}
	})
}

func TestVictimListUnmarshal(t *testing.T) {
	t.Run("plain array", func(t *testing.T) {
		var vl VictimList
		if err := json.Unmarshal([]byte(`[{"victim":"v1","group":"g1"}]`), &vl); err != nil {
			t.Fatal(err)
		}
		if len(vl) != 1 || vl[0].Victim != "v1" {
			t.Fatalf("bad plain array: %+v", vl)
		}
	})

	for _, key := range []string{"data", "victims", "results", "items", "entries"} {
		t.Run("envelope "+key, func(t *testing.T) {
			var vl VictimList
			body := `{"` + key + `":[{"victim":"v1","group":"g1"}],"count":1}`
			if err := json.Unmarshal([]byte(body), &vl); err != nil {
				t.Fatal(err)
			}
			if len(vl) != 1 || vl[0].Victim != "v1" {
				t.Fatalf("bad %s envelope: %+v", key, vl)
			}
		})
	}

	t.Run("empty envelope", func(t *testing.T) {
		var vl VictimList
		if err := json.Unmarshal([]byte(`{"victims":[]}`), &vl); err != nil {
			t.Fatal(err)
		}
		if len(vl) != 0 {
			t.Fatalf("expected empty list, got %+v", vl)
		}
	})

	t.Run("message", func(t *testing.T) {
		var vl VictimList
		err := json.Unmarshal([]byte(`{"message":"no victims found"}`), &vl)
		if err == nil || !strings.Contains(err.Error(), "no victims found") {
			t.Fatalf("expected message error, got %v", err)
		}
	})

	t.Run("unexpected object", func(t *testing.T) {
		var vl VictimList
		if err := json.Unmarshal([]byte(`{"foo":"bar"}`), &vl); err == nil {
			t.Fatal("expected error for unexpected object")
		}
	})
}

func TestListVictimsObjectEnvelope(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/victims/" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("year") != "2026" || q.Get("month") != "05" {
			t.Fatalf("bad query: %v", q)
		}
		_, _ = io.WriteString(w, `{"data":[{"victim":"v1","group":"g1","activity":"Healthcare"}],"count":1}`)
	})
	defer ts.Close()

	out, err := c.ListVictims(VictimFilter{Year: "2026", Month: "05"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Victim != "v1" || out[0].Activity != "Healthcare" {
		t.Fatalf("bad envelope decode: %+v", out)
	}
}

func TestGetRecentVictimsObjectEnvelope(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"victims":[{"victim":"v1","group":"g1"}],"count":1}`)
	})
	defer ts.Close()

	out, err := c.GetRecentVictims("")
	if err != nil || len(out) != 1 || out[0].Victim != "v1" {
		t.Fatalf("bad recent envelope decode: %+v, %v", out, err)
	}
}

func TestSearchVictimsObjectEnvelope(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"results":[{"victim":"v1","group":"g1"}]}`)
	})
	defer ts.Close()

	out, err := c.SearchVictims("hospital", VictimFilter{})
	if err != nil || len(out) != 1 || out[0].Victim != "v1" {
		t.Fatalf("bad search envelope decode: %+v, %v", out, err)
	}
}

func TestSearchVictims(t *testing.T) {
	t.Run("empty query", func(t *testing.T) {
		c := NewClient("k")
		_, err := c.SearchVictims("", VictimFilter{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("query and filters", func(t *testing.T) {
		c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/victims/search" {
				t.Fatalf("bad path %s", r.URL.Path)
			}
			q := r.URL.Query()
			if q.Get("q") != "hospital" || q.Get("country") != "FR" || q.Get("order") != "discovered" {
				t.Fatalf("bad query: %v", q)
			}
			for _, undocumented := range []string{"year", "month", "date"} {
				if q.Get(undocumented) != "" {
					t.Fatalf("undocumented param sent: %s", undocumented)
				}
			}
			_, _ = io.WriteString(w, `[{"victim":"v1","group":"g1"}]`)
		})
		defer ts.Close()

		out, err := c.SearchVictims("hospital", VictimFilter{Country: "FR", Order: "discovered"})
		if err != nil || len(out) != 1 {
			t.Fatal("bad search victims")
		}
	})
}

func TestGetVictim(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/victim/QWNtZQ==" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"victim":"v1","group":"g1","description":"d","sector":"Education","extra":{"press_coverage":[{"title":"t","url":"u"}]}}`)
	})
	defer ts.Close()

	out, err := c.GetVictim("QWNtZQ==")
	if err != nil || out.Victim != "v1" || out.Description != "d" {
		t.Fatal("bad get victim")
	}
	if out.Sector != "Education" || out.Activity != "Education" {
		t.Fatal("sector/activity alias failed")
	}
	if len(out.Extra.PressCoverage) != 1 || out.Extra.PressCoverage[0].Title != "t" {
		t.Fatal("bad extra press coverage")
	}
}

func TestListIOCGroups(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") != "md5" {
			t.Fatal("bad type")
		}
		_, _ = io.WriteString(w, `[{"group":"g1","types":{"md5":1,"url":2}}]`)
	})
	defer ts.Close()

	out, err := c.ListIOCGroups("md5")
	if err != nil || len(out) != 1 || out[0].Group != "g1" {
		t.Fatal("bad ioc groups")
	}
	if out[0].Types.MD5 != 1 || out[0].Types.URL != 2 {
		t.Fatal("bad ioc type counts")
	}
}

func TestGetGroupIOCs(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/iocs/g1" || r.URL.Query().Get("type") != "url" {
			t.Fatalf("bad request: %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		_, _ = io.WriteString(w, `{"group":"g1","md5":["a"],"url":["http://x"]}`)
	})
	defer ts.Close()

	out, err := c.GetGroupIOCs("g1", "url")
	if err != nil || out.Group != "g1" || len(out.MD5) != 1 || len(out.URL) != 1 {
		t.Fatal("bad group iocs")
	}
}

func TestListNegotiationGroups(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `[{"group":"g1","chats":2}]`)
	})
	defer ts.Close()

	out, err := c.ListNegotiationGroups()
	if err != nil || len(out) != 1 || out[0].Chats != 2 {
		t.Fatal("bad negotiation groups")
	}
}

func TestListNegotiationChats(t *testing.T) {
	t.Run("documented names", func(t *testing.T) {
		c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/negotiations/g1" {
				t.Fatalf("bad path %s", r.URL.Path)
			}
			_, _ = io.WriteString(w, `[{"id":"c1","message_count":3,"initialransom":"100k","negotiatedransom":"50k","paid":true}]`)
		})
		defer ts.Close()

		out, err := c.ListNegotiationChats("g1")
		if err != nil || len(out) != 1 {
			t.Fatal("bad negotiation chats")
		}
		chat := out[0]
		if chat.ID != "c1" || chat.MessageCount != 3 || chat.InitialRansom != "100k" ||
			chat.NegotiatedRansom == nil || *chat.NegotiatedRansom != "50k" || !chat.Paid {
			t.Fatalf("bad chat fields: %+v", chat)
		}
	})

	t.Run("legacy names", func(t *testing.T) {
		c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `[{"id":"c1","messages":3,"initial_ransom":"100k","negotiated_ransom":null,"paid":false}]`)
		})
		defer ts.Close()

		out, err := c.ListNegotiationChats("g1")
		if err != nil || len(out) != 1 {
			t.Fatal("bad negotiation chats")
		}
		chat := out[0]
		if chat.MessageCount != 3 || chat.InitialRansom != "100k" || chat.NegotiatedRansom != nil {
			t.Fatalf("bad legacy chat fields: %+v", chat)
		}
	})
}

func TestGetNegotiationChat(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/negotiations/g1/c1" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{
			"id":"c1",
			"message_count":1,
			"messages":[{"sender":"attacker","timestamp":"2026-07-12T00:00:00Z","content":"hi"}],
			"initialransom":"100k",
			"negotiatedransom":null,
			"paid":false
		}`)
	})
	defer ts.Close()

	out, err := c.GetNegotiationChat("g1", "c1")
	if err != nil || out.ID != "c1" || out.MessageCount != 1 {
		t.Fatal("bad negotiation chat")
	}
	if len(out.Messages) != 1 || out.Messages[0].Sender != "attacker" || out.Messages[0].Timestamp != "2026-07-12T00:00:00Z" {
		t.Fatal("bad messages")
	}
	if out.InitialRansom != "100k" || out.NegotiatedRansom != nil {
		t.Fatal("bad ransom fields")
	}
}

func TestListRansomNoteGroups(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `[{"group":"g1","notes":1}]`)
	})
	defer ts.Close()

	out, err := c.ListRansomNoteGroups()
	if err != nil || len(out) != 1 || out[0].Notes != 1 {
		t.Fatal("bad ransom note groups")
	}
}

func TestListRansomNotes(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ransomnotes/g1" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `["note1","note2"]`)
	})
	defer ts.Close()

	out, err := c.ListRansomNotes("g1")
	if err != nil || len(out) != 2 || out[0] != "note1" {
		t.Fatal("bad ransom notes")
	}
}

func TestGetRansomNote(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ransomnotes/g1/note1" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"extension":".txt","content":"hello"}`)
	})
	defer ts.Close()

	out, err := c.GetRansomNote("g1", "note1")
	if err != nil || out.Extension != ".txt" || out.Content != "hello" {
		t.Fatal("bad ransom note")
	}
}

func TestListYARAGroups(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `[{"group":"g1","rules":1}]`)
	})
	defer ts.Close()

	out, err := c.ListYARAGroups()
	if err != nil || len(out) != 1 || out[0].Rules != 1 {
		t.Fatal("bad yara groups")
	}
}

func TestGetYARARules(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/yara/g1" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `[{"filename":"a.yar","content":"rule a"}]`)
	})
	defer ts.Close()

	out, err := c.GetYARARules("g1")
	if err != nil || len(out) != 1 || out[0].Filename != "a.yar" {
		t.Fatal("bad yara rules")
	}
}

func TestListPressEntries(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("year") != "2026" || r.URL.Query().Get("month") != "06" ||
			r.URL.Query().Get("country") != "US" {
			t.Fatalf("bad query: %v", r.URL.Query())
		}
		_, _ = io.WriteString(w, `[{"id":"1","title":"t"}]`)
	})
	defer ts.Close()

	out, err := c.ListPressEntries("2026", "06", "US")
	if err != nil || len(out) != 1 || out[0].ID != "1" {
		t.Fatal("bad press entries")
	}
}

func TestGetRecentPressEntries(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("country") != "US" {
			t.Fatal("bad country")
		}
		_, _ = io.WriteString(w, `[{"id":"1","title":"t"}]`)
	})
	defer ts.Close()

	out, err := c.GetRecentPressEntries("US")
	if err != nil || len(out) != 1 || out[0].ID != "1" {
		t.Fatal("bad recent press entries")
	}
}

func TestGetCSIRTContacts(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/csirt/US" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `[{"name":"CERT","email":"a@b.com","country_code":"US"}]`)
	})
	defer ts.Close()

	out, err := c.GetCSIRTContacts("US")
	if err != nil || len(out) != 1 || out[0].Name != "CERT" || out[0].CountryCode != "US" {
		t.Fatal("bad csirt contacts")
	}
}

func TestGetSECFilings(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("ticker") != "AAPL" || q.Get("item105") != "false" || q.Get("item801") != "true" {
			t.Fatalf("bad sec query: %v", q)
		}
		_, _ = io.WriteString(w, `[{"id":"1","ticker":"AAPL"}]`)
	})
	defer ts.Close()

	out, err := c.GetSECFilings("AAPL", "", "", "", false, true)
	if err != nil || len(out) != 1 || out[0].Ticker != "AAPL" {
		t.Fatal("bad sec filings")
	}
}

func TestListSectors(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `[{"sector":"Healthcare","count":1}]`)
	})
	defer ts.Close()

	out, err := c.ListSectors()
	if err != nil || len(out) != 1 || out[0].Sector != "Healthcare" {
		t.Fatal("bad sectors")
	}
}

func TestGetStats(t *testing.T) {
	t.Run("documented nested shape", func(t *testing.T) {
		c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"stats":{"victims":1,"groups":2,"press":3},"last_update":"2026-07-12T00:00:00Z"}`)
		})
		defer ts.Close()

		out, err := c.GetStats()
		if err != nil || out.Stats.Victims != 1 || out.Stats.Groups != 2 || out.Stats.Press != 3 {
			t.Fatal("bad stats")
		}
		if out.LastUpdate != "2026-07-12T00:00:00Z" {
			t.Fatal("bad last update")
		}
	})

	t.Run("legacy flat shape", func(t *testing.T) {
		c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"total_victims":1,"total_groups":2,"total_press":3,"last_discovered":"2026-07-12"}`)
		})
		defer ts.Close()

		out, err := c.GetStats()
		if err != nil || out.Stats.Victims != 1 || out.Stats.Groups != 2 || out.Stats.Press != 3 {
			t.Fatal("bad legacy stats")
		}
		if out.LastUpdate != "2026-07-12" {
			t.Fatal("bad last update alias")
		}
	})
}

func TestValidateKey(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/validate" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"valid":true,"client_id":"abc"}`)
	})
	defer ts.Close()

	out, err := c.ValidateKey()
	if err != nil || !out.Valid || out.ClientID != "abc" {
		t.Fatal("bad validate key")
	}
}

func TestPathEscaping(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/groups/a%20b%2Fc" {
			t.Fatalf("bad escaped path %s", r.URL.EscapedPath())
		}
		_, _ = io.WriteString(w, `{"group":"a b/c"}`)
	})
	defer ts.Close()

	out, err := c.GetGroup("a b/c")
	if err != nil || out.Group != "a b/c" {
		t.Fatal("bad escaped group")
	}
}

func TestContextCancellation(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(2 * time.Second):
			_, _ = io.WriteString(w, `[]`)
		}
	})
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.GetRecentVictimsWithContext(ctx, ""); err == nil {
		t.Fatal("expected context error")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

package ransomware

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Each test below mirrors a public method in main.go and exercises its
// WithContext variant directly, verifying path, query parameters and the
// decoded result.

func TestListGroupsWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/groups" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `[{"group":"lockbit","altname":"LockBit 3.0","victims":10}]`)
	})
	defer ts.Close()

	out, err := c.ListGroupsWithContext(context.Background())
	if err != nil || len(out) != 1 || out[0].Group != "lockbit" || out[0].Victims != 10 {
		t.Fatal("bad list groups with context")
	}
	if out[0].AltName == nil || *out[0].AltName != "LockBit 3.0" {
		t.Fatal("bad altname")
	}
}

func TestGetGroupWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/groups/lockbit" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"group":"lockbit","description":"d","victims":1,"has_negotiations":true,"negotiation_count":2}`)
	})
	defer ts.Close()

	out, err := c.GetGroupWithContext(context.Background(), "lockbit")
	if err != nil || out.Group != "lockbit" || out.Description != "d" {
		t.Fatal("bad get group with context")
	}
	if !out.HasNegotiations || out.NegotiationCount != 2 {
		t.Fatal("bad negotiation flags")
	}
}

func TestGetGroupCompatWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/group/lockbit" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"group":"lockbit"}`)
	})
	defer ts.Close()

	out, err := c.GetGroupCompatWithContext(context.Background(), "lockbit")
	if err != nil || out.Group != "lockbit" {
		t.Fatal("bad get group compat with context")
	}
}

func TestGetRecentVictimsWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("order") != "attacked" {
			t.Fatal("bad order")
		}
		_, _ = io.WriteString(w, `[{"id":"a","victim":"v1","group":"g1","activity":"Healthcare","website":"v1.com","permalink":"https://x/id/a"}]`)
	})
	defer ts.Close()

	out, err := c.GetRecentVictimsWithContext(context.Background(), "attacked")
	if err != nil || len(out) != 1 || out[0].Victim != "v1" {
		t.Fatal("bad recent victims with context")
	}
	if out[0].Activity != "Healthcare" || out[0].Sector != "Healthcare" {
		t.Fatal("activity/sector alias failed")
	}
}

func TestListVictimsWithContext(t *testing.T) {
	t.Run("filters", func(t *testing.T) {
		c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/victims/" {
				t.Fatalf("bad path %s", r.URL.Path)
			}
			q := r.URL.Query()
			if q.Get("group") != "g1" || q.Get("country") != "US" ||
				q.Get("year") != "2026" || q.Get("month") != "06" || q.Get("date") != "attacked" {
				t.Fatalf("bad filters: %v", q)
			}
			_, _ = io.WriteString(w, `[{"victim":"v1","group":"g1"}]`)
		})
		defer ts.Close()

		out, err := c.ListVictimsWithContext(context.Background(), VictimFilter{
			Group: "g1", Country: "US", Year: "2026", Month: "06", Date: "attacked",
		})
		if err != nil || len(out) != 1 || out[0].Victim != "v1" {
			t.Fatal("bad list victims with context")
		}
	})

	t.Run("sector and order", func(t *testing.T) {
		c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			if q.Get("sector") != "Healthcare" || q.Get("order") != "attacked" {
				t.Fatalf("bad filters: %v", q)
			}
			_, _ = io.WriteString(w, `[{"victim":"v1"}]`)
		})
		defer ts.Close()

		out, err := c.ListVictimsWithContext(context.Background(), VictimFilter{Sector: "Healthcare", Order: "attacked"})
		if err != nil || len(out) != 1 {
			t.Fatal("bad list victims with sector/order")
		}
	})

	t.Run("validation error", func(t *testing.T) {
		c := NewClient("k")
		_, err := c.ListVictimsWithContext(context.Background(), VictimFilter{Year: "2026"})
		if err == nil {
			t.Fatal("expected year/month validation error")
		}
	})

	t.Run("month without year", func(t *testing.T) {
		c := NewClient("k")
		_, err := c.ListVictimsWithContext(context.Background(), VictimFilter{Month: "06"})
		if err == nil {
			t.Fatal("expected month/year validation error")
		}
	})
}

func TestSearchVictimsWithContext(t *testing.T) {
	t.Run("empty query", func(t *testing.T) {
		c := NewClient("k")
		_, err := c.SearchVictimsWithContext(context.Background(), "", VictimFilter{})
		if err == nil {
			t.Fatal("expected empty query error")
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

		out, err := c.SearchVictimsWithContext(context.Background(), "hospital", VictimFilter{Country: "FR", Order: "discovered"})
		if err != nil || len(out) != 1 {
			t.Fatal("bad search victims with context")
		}
	})

	t.Run("group and sector filters", func(t *testing.T) {
		c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			if q.Get("q") != "hospital" || q.Get("group") != "lockbit" || q.Get("sector") != "Healthcare" {
				t.Fatalf("bad query: %v", q)
			}
			_, _ = io.WriteString(w, `[{"victim":"v1"}]`)
		})
		defer ts.Close()

		out, err := c.SearchVictimsWithContext(context.Background(), "hospital", VictimFilter{Group: "lockbit", Sector: "Healthcare"})
		if err != nil || len(out) != 1 {
			t.Fatal("bad search victims with group/sector")
		}
	})
}

func TestGetVictimWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/victim/QWNtZQ==" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"victim":"v1","group":"g1","description":"d","sector":"Education"}`)
	})
	defer ts.Close()

	out, err := c.GetVictimWithContext(context.Background(), "QWNtZQ==")
	if err != nil || out.Victim != "v1" || out.Description != "d" {
		t.Fatal("bad get victim with context")
	}
	if out.Sector != "Education" || out.Activity != "Education" {
		t.Fatal("sector/activity alias failed")
	}
}

func TestListIOCGroupsWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") != "md5" {
			t.Fatal("bad type")
		}
		_, _ = io.WriteString(w, `[{"group":"g1","types":{"md5":1,"url":2}}]`)
	})
	defer ts.Close()

	out, err := c.ListIOCGroupsWithContext(context.Background(), "md5")
	if err != nil || len(out) != 1 || out[0].Group != "g1" {
		t.Fatal("bad ioc groups with context")
	}
	if out[0].Types.MD5 != 1 || out[0].Types.URL != 2 {
		t.Fatal("bad ioc type counts")
	}
}

func TestGetGroupIOCsWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/iocs/g1" || r.URL.Query().Get("type") != "url" {
			t.Fatalf("bad request: %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		_, _ = io.WriteString(w, `{"group":"g1","md5":["a"],"url":["http://x"]}`)
	})
	defer ts.Close()

	out, err := c.GetGroupIOCsWithContext(context.Background(), "g1", "url")
	if err != nil || out.Group != "g1" || len(out.MD5) != 1 || len(out.URL) != 1 {
		t.Fatal("bad group iocs with context")
	}
}

func TestListNegotiationGroupsWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/negotiations" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `[{"group":"g1","chats":2}]`)
	})
	defer ts.Close()

	out, err := c.ListNegotiationGroupsWithContext(context.Background())
	if err != nil || len(out) != 1 || out[0].Chats != 2 {
		t.Fatal("bad negotiation groups with context")
	}
}

func TestListNegotiationChatsWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/negotiations/g1" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `[{"id":"c1","message_count":3,"initialransom":"100k","negotiatedransom":"50k","paid":true}]`)
	})
	defer ts.Close()

	out, err := c.ListNegotiationChatsWithContext(context.Background(), "g1")
	if err != nil || len(out) != 1 {
		t.Fatal("bad negotiation chats with context")
	}
	chat := out[0]
	if chat.ID != "c1" || chat.MessageCount != 3 || chat.InitialRansom != "100k" ||
		chat.NegotiatedRansom == nil || *chat.NegotiatedRansom != "50k" || !chat.Paid {
		t.Fatalf("bad chat fields: %+v", chat)
	}
}

func TestGetNegotiationChatWithContext(t *testing.T) {
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

	out, err := c.GetNegotiationChatWithContext(context.Background(), "g1", "c1")
	if err != nil || out.ID != "c1" || out.MessageCount != 1 {
		t.Fatal("bad negotiation chat with context")
	}
	if len(out.Messages) != 1 || out.Messages[0].Sender != "attacker" || out.Messages[0].Timestamp != "2026-07-12T00:00:00Z" {
		t.Fatal("bad messages")
	}
	if out.InitialRansom != "100k" || out.NegotiatedRansom != nil {
		t.Fatal("bad ransom fields")
	}
}

func TestListRansomNoteGroupsWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ransomnotes" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `[{"group":"g1","notes":1}]`)
	})
	defer ts.Close()

	out, err := c.ListRansomNoteGroupsWithContext(context.Background())
	if err != nil || len(out) != 1 || out[0].Notes != 1 {
		t.Fatal("bad ransom note groups with context")
	}
}

func TestListRansomNotesWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ransomnotes/g1" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `["note1","note2"]`)
	})
	defer ts.Close()

	out, err := c.ListRansomNotesWithContext(context.Background(), "g1")
	if err != nil || len(out) != 2 || out[0] != "note1" {
		t.Fatal("bad ransom notes with context")
	}
}

func TestGetRansomNoteWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ransomnotes/g1/note1" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"extension":".txt","content":"hello"}`)
	})
	defer ts.Close()

	out, err := c.GetRansomNoteWithContext(context.Background(), "g1", "note1")
	if err != nil || out.Extension != ".txt" || out.Content != "hello" {
		t.Fatal("bad ransom note with context")
	}
}

func TestListYARAGroupsWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/yara" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `[{"group":"g1","rules":1}]`)
	})
	defer ts.Close()

	out, err := c.ListYARAGroupsWithContext(context.Background())
	if err != nil || len(out) != 1 || out[0].Rules != 1 {
		t.Fatal("bad yara groups with context")
	}
}

func TestGetYARARulesWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/yara/g1" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `[{"filename":"a.yar","content":"rule a"}]`)
	})
	defer ts.Close()

	out, err := c.GetYARARulesWithContext(context.Background(), "g1")
	if err != nil || len(out) != 1 || out[0].Filename != "a.yar" {
		t.Fatal("bad yara rules with context")
	}
}

func TestListPressEntriesWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/press/all" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("year") != "2026" || q.Get("month") != "06" || q.Get("country") != "US" {
			t.Fatalf("bad query: %v", q)
		}
		_, _ = io.WriteString(w, `[{"id":"1","title":"t"}]`)
	})
	defer ts.Close()

	out, err := c.ListPressEntriesWithContext(context.Background(), "2026", "06", "US")
	if err != nil || len(out) != 1 || out[0].ID != "1" {
		t.Fatal("bad press entries with context")
	}
}

func TestGetRecentPressEntriesWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/press/recent" || r.URL.Query().Get("country") != "US" {
			t.Fatalf("bad request: %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		_, _ = io.WriteString(w, `[{"id":"1","title":"t"}]`)
	})
	defer ts.Close()

	out, err := c.GetRecentPressEntriesWithContext(context.Background(), "US")
	if err != nil || len(out) != 1 || out[0].ID != "1" {
		t.Fatal("bad recent press entries with context")
	}
}

func TestGetCSIRTContactsWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/csirt/US" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `[{"name":"CERT","email":"a@b.com","country_code":"US"}]`)
	})
	defer ts.Close()

	out, err := c.GetCSIRTContactsWithContext(context.Background(), "US")
	if err != nil || len(out) != 1 || out[0].Name != "CERT" {
		t.Fatal("bad csirt contacts with context")
	}
}

func TestGetSECFilingsWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/8k" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("ticker") != "MSFT" || q.Get("cik") != "0000789019" ||
			q.Get("year") != "2025" || q.Get("month") != "06" ||
			q.Get("item105") != "false" || q.Get("item801") != "true" {
			t.Fatalf("bad sec query: %v", q)
		}
		_, _ = io.WriteString(w, `[{"id":"1","ticker":"MSFT"}]`)
	})
	defer ts.Close()

	out, err := c.GetSECFilingsWithContext(context.Background(), "MSFT", "0000789019", "2025", "06", false, true)
	if err != nil || len(out) != 1 || out[0].Ticker != "MSFT" {
		t.Fatal("bad sec filings with context")
	}
}

func TestListSectorsWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/listsectors" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `[{"sector":"Healthcare","count":1}]`)
	})
	defer ts.Close()

	out, err := c.ListSectorsWithContext(context.Background())
	if err != nil || len(out) != 1 || out[0].Sector != "Healthcare" {
		t.Fatal("bad sectors with context")
	}
}

func TestGetStatsWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stats" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"stats":{"victims":1,"groups":2,"press":3},"last_update":"2026-07-12T00:00:00Z"}`)
	})
	defer ts.Close()

	out, err := c.GetStatsWithContext(context.Background())
	if err != nil || out.Stats.Victims != 1 || out.Stats.Groups != 2 || out.Stats.Press != 3 {
		t.Fatal("bad stats with context")
	}
	if out.LastUpdate != "2026-07-12T00:00:00Z" {
		t.Fatal("bad last update")
	}
}

func TestValidateKeyWithContext(t *testing.T) {
	c, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/validate" {
			t.Fatalf("bad path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"valid":true,"client_id":"abc"}`)
	})
	defer ts.Close()

	out, err := c.ValidateKeyWithContext(context.Background())
	if err != nil || !out.Valid || out.ClientID != "abc" {
		t.Fatal("bad validate key with context")
	}
}

// Dedicated UnmarshalJSON tests mirroring the flexible-list and alias
// handling implemented in main.go.

func TestLocationListUnmarshal(t *testing.T) {
	var obj LocationList
	if err := json.Unmarshal([]byte(`[{"available":true,"enabled":true,"fqdn":"x.onion","slug":"http://x.onion","title":"t","type":"DLS"}]`), &obj); err != nil {
		t.Fatal(err)
	}
	if len(obj) != 1 || !obj[0].Available || obj[0].FQDN != "x.onion" {
		t.Fatalf("bad object form: %+v", obj)
	}

	var str LocationList
	if err := json.Unmarshal([]byte(`["http://a.onion","http://b.onion"]`), &str); err != nil {
		t.Fatal(err)
	}
	if len(str) != 2 || str[0].Slug != "http://a.onion" {
		t.Fatalf("bad string form: %+v", str)
	}

	var bad LocationList
	if err := json.Unmarshal([]byte(`{"not":"a list"}`), &bad); err == nil {
		t.Fatal("expected error for invalid payload")
	}
}

func TestTTPListUnmarshal(t *testing.T) {
	var obj TTPList
	if err := json.Unmarshal([]byte(`[{"tactic_id":"TA0001","tactic_name":"Initial Access","techniques":[{"technique_id":"T1078","technique_name":"Valid Accounts"}]}]`), &obj); err != nil {
		t.Fatal(err)
	}
	if len(obj) != 1 || obj[0].TacticName != "Initial Access" || len(obj[0].Techniques) != 1 {
		t.Fatalf("bad object form: %+v", obj)
	}

	var str TTPList
	if err := json.Unmarshal([]byte(`["T1078","T1133"]`), &str); err != nil {
		t.Fatal(err)
	}
	if len(str) != 2 || str[0].TechniqueName != "T1078" {
		t.Fatalf("bad string form: %+v", str)
	}

	var bad TTPList
	if err := json.Unmarshal([]byte(`123`), &bad); err == nil {
		t.Fatal("expected error for invalid payload")
	}
}

func TestVulnerabilityListUnmarshal(t *testing.T) {
	var obj VulnerabilityList
	if err := json.Unmarshal([]byte(`[{"id":"CVE-2024-1234","cvss":9.1}]`), &obj); err != nil {
		t.Fatal(err)
	}
	if len(obj) != 1 || obj[0].ID != "CVE-2024-1234" || obj[0].CVSS != 9.1 {
		t.Fatalf("bad object form: %+v", obj)
	}

	var str VulnerabilityList
	if err := json.Unmarshal([]byte(`["CVE-1","CVE-2"]`), &str); err != nil {
		t.Fatal(err)
	}
	if len(str) != 2 || str[0].ID != "CVE-1" {
		t.Fatalf("bad string form: %+v", str)
	}

	var bad VulnerabilityList
	if err := json.Unmarshal([]byte(`123`), &bad); err == nil {
		t.Fatal("expected error for invalid payload")
	}
}

func TestVictimUnmarshal(t *testing.T) {
	t.Run("documented names", func(t *testing.T) {
		var v Victim
		if err := json.Unmarshal([]byte(`{"victim":"v1","group":"g1","activity":"Healthcare","website":"v1.com","permalink":"https://x/id/a"}`), &v); err != nil {
			t.Fatal(err)
		}
		if v.Activity != "Healthcare" || v.Sector != "Healthcare" ||
			v.Website != "v1.com" || v.Domain != "v1.com" ||
			v.Permalink != "https://x/id/a" || v.URL != "https://x/id/a" {
			t.Fatalf("bad alias mapping: %+v", v)
		}
	})

	t.Run("legacy names", func(t *testing.T) {
		var v Victim
		if err := json.Unmarshal([]byte(`{"victim":"v1","group":"g1","sector":"Education","domain":"e.com","url":"https://x/id/b"}`), &v); err != nil {
			t.Fatal(err)
		}
		if v.Activity != "Education" || v.Sector != "Education" ||
			v.Website != "e.com" || v.Domain != "e.com" ||
			v.Permalink != "https://x/id/b" || v.URL != "https://x/id/b" {
			t.Fatalf("bad legacy alias mapping: %+v", v)
		}
	})

	t.Run("empty fields", func(t *testing.T) {
		var v Victim
		if err := json.Unmarshal([]byte(`{"victim":"v1"}`), &v); err != nil {
			t.Fatal(err)
		}
		if v.Activity != "" || v.Sector != "" || v.Website != "" || v.Domain != "" {
			t.Fatalf("expected empty alias fields: %+v", v)
		}
	})

	t.Run("type mismatch", func(t *testing.T) {
		var v Victim
		if err := json.Unmarshal([]byte(`{"activity":123}`), &v); err == nil {
			t.Fatal("expected decode error")
		}
	})
}

func TestVictimDetailUnmarshal(t *testing.T) {
	var v VictimDetail
	if err := json.Unmarshal([]byte(`{
		"victim":"v1","group":"g1","sector":"Education","domain":"e.com",
		"description":"d",
		"extra":{"press_coverage":[{"title":"t","url":"u","source":"s","date":"2026-07-12"}]}
	}`), &v); err != nil {
		t.Fatal(err)
	}
	if v.Activity != "Education" || v.Sector != "Education" || v.Website != "e.com" || v.Description != "d" {
		t.Fatalf("bad victim detail: %+v", v)
	}
	if len(v.Extra.PressCoverage) != 1 || v.Extra.PressCoverage[0].Source != "s" {
		t.Fatalf("bad extra: %+v", v.Extra)
	}

	if err := json.Unmarshal([]byte(`{"activity":123}`), &v); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestNegotiationChatUnmarshal(t *testing.T) {
	t.Run("documented names", func(t *testing.T) {
		var n NegotiationChat
		if err := json.Unmarshal([]byte(`{"id":"c1","message_count":3,"initialransom":"100k","negotiatedransom":"50k","paid":true}`), &n); err != nil {
			t.Fatal(err)
		}
		if n.MessageCount != 3 || n.InitialRansom != "100k" || n.NegotiatedRansom == nil || *n.NegotiatedRansom != "50k" || !n.Paid {
			t.Fatalf("bad chat: %+v", n)
		}
	})

	t.Run("legacy names", func(t *testing.T) {
		var n NegotiationChat
		if err := json.Unmarshal([]byte(`{"id":"c1","messages":3,"initial_ransom":"100k","negotiated_ransom":null,"paid":false}`), &n); err != nil {
			t.Fatal(err)
		}
		if n.MessageCount != 3 || n.InitialRansom != "100k" || n.NegotiatedRansom != nil || n.Paid {
			t.Fatalf("bad legacy chat: %+v", n)
		}
	})

	t.Run("type mismatch", func(t *testing.T) {
		var n NegotiationChat
		if err := json.Unmarshal([]byte(`{"id":123}`), &n); err == nil {
			t.Fatal("expected decode error")
		}
	})
}

func TestNegotiationChatDetailUnmarshal(t *testing.T) {
	t.Run("documented names", func(t *testing.T) {
		var n NegotiationChatDetail
		if err := json.Unmarshal([]byte(`{"id":"c1","message_count":1,"messages":[{"sender":"a","timestamp":"2026-07-12","content":"hi"}],"initialransom":"100k","negotiatedransom":null,"paid":false}`), &n); err != nil {
			t.Fatal(err)
		}
		if n.MessageCount != 1 || n.InitialRansom != "100k" || len(n.Messages) != 1 {
			t.Fatalf("bad detail: %+v", n)
		}
	})

	t.Run("legacy names", func(t *testing.T) {
		var n NegotiationChatDetail
		if err := json.Unmarshal([]byte(`{"id":"c1","messages":[],"initial_ransom":"100k","negotiated_ransom":"20k","paid":true}`), &n); err != nil {
			t.Fatal(err)
		}
		if n.InitialRansom != "100k" || n.NegotiatedRansom == nil || *n.NegotiatedRansom != "20k" || !n.Paid {
			t.Fatalf("bad legacy detail: %+v", n)
		}
	})

	t.Run("type mismatch", func(t *testing.T) {
		var n NegotiationChatDetail
		if err := json.Unmarshal([]byte(`{"id":123}`), &n); err == nil {
			t.Fatal("expected decode error")
		}
	})
}

func TestStatsUnmarshal(t *testing.T) {
	t.Run("documented nested shape", func(t *testing.T) {
		var s Stats
		if err := json.Unmarshal([]byte(`{"stats":{"victims":1,"groups":2,"press":3},"last_update":"2026-07-12T00:00:00Z"}`), &s); err != nil {
			t.Fatal(err)
		}
		if s.Stats.Victims != 1 || s.Stats.Groups != 2 || s.Stats.Press != 3 || s.LastUpdate != "2026-07-12T00:00:00Z" {
			t.Fatalf("bad nested stats: %+v", s)
		}
	})

	t.Run("legacy flat shape", func(t *testing.T) {
		var s Stats
		if err := json.Unmarshal([]byte(`{"total_victims":4,"total_groups":5,"total_press":6,"last_discovered":"2026-07-12"}`), &s); err != nil {
			t.Fatal(err)
		}
		if s.Stats.Victims != 4 || s.Stats.Groups != 5 || s.Stats.Press != 6 || s.LastUpdate != "2026-07-12" {
			t.Fatalf("bad flat stats: %+v", s)
		}
	})

	t.Run("type mismatch", func(t *testing.T) {
		var s Stats
		if err := json.Unmarshal([]byte(`{"stats":123}`), &s); err == nil {
			t.Fatal("expected decode error")
		}
	})
}

func TestAPIErrorFormatting(t *testing.T) {
	short := &APIError{Method: "GET", Path: "https://x/stats", StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: "gone"}
	msg := short.Error()
	if !strings.Contains(msg, "GET") || !strings.Contains(msg, "https://x/stats") ||
		!strings.Contains(msg, "404") || !strings.Contains(msg, "gone") {
		t.Fatalf("bad error message: %s", msg)
	}

	long := &APIError{Method: "GET", Path: "p", StatusCode: http.StatusBadRequest, Status: "400 Bad Request", Body: strings.Repeat("x", maxErrorBodyLen*2)}
	if len(long.Error()) >= maxErrorBodyLen*2 {
		t.Fatal("long body should be truncated")
	}
}

func TestAsAPIErrorNonAPIError(t *testing.T) {
	if apiErr, ok := AsAPIError(errors.New("plain")); ok || apiErr != nil {
		t.Fatal("plain errors should not unwrap to APIError")
	}
	if IsAPIError(errors.New("plain")) {
		t.Fatal("IsAPIError should be false for plain errors")
	}
}

func TestGetRequestBuildError(t *testing.T) {
	c := NewClient("key", WithBaseURL("://bad"))
	if _, err := c.ListGroupsWithContext(context.Background()); err == nil {
		t.Fatal("expected request build error")
	}
}

func TestDecodeResponseReadError(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(errReader{}),
	}
	if err := decodeResponse("GET", "https://x/stats", resp, nil); err == nil {
		t.Fatal("expected read error")
	}
}

func TestDecodeResponseNilOut(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(strings.NewReader(`{}`)),
	}
	if err := decodeResponse("GET", "https://x/stats", resp, nil); err != nil {
		t.Fatal(err)
	}
}

func TestEscapePath(t *testing.T) {
	if got := escapePath("a", "", "b c"); got != "/a/b%20c" {
		t.Fatalf("bad escaped path %q", got)
	}
	if got := escapePath("groups", "lockbit"); got != "/groups/lockbit" {
		t.Fatalf("bad plain path %q", got)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read boom") }

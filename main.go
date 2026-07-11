package ransomware

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const DefaultBaseURL = "https://api-pro.ransomware.live/"
const DefaultTimeout = 30 * time.Second

type Client struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
}

type Option func(*Client)

func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) { cl.httpClient = c }
}

func WithBaseURL(baseURL string) Option {
	return func(cl *Client) { cl.baseURL = baseURL }
}

func NewClient(apiKey string, opts ...Option) *Client {
	c := &Client{
		httpClient: &http.Client{Timeout: DefaultTimeout},
		baseURL:    DefaultBaseURL,
		apiKey:     apiKey,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Client) doRequest(method, path string, params url.Values, result interface{}) error {
	reqURL := c.baseURL + path
	if params != nil && len(params) > 0 {
		reqURL += "?" + params.Encode()
	}
	req, err := http.NewRequest(method, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-KEY", c.apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	if result != nil {
		return json.Unmarshal(body, result)
	}
	return nil
}

type GroupSummary struct {
	Group   string `json:"group"`
	Victims int    `json:"victims"`
}

func (c *Client) ListGroups() ([]GroupSummary, error) {
	var out []GroupSummary
	err := c.doRequest("GET", "groups", nil, &out)
	return out, err
}

type GroupDetail struct {
	Group          string   `json:"group"`
	Description    string   `json:"description"`
	Victims        int      `json:"victims"`
	FirstSeen      string   `json:"firstseen"`
	LastSeen       string   `json:"lastseen"`
	Locations      []string `json:"locations"`
	TTPs           []string `json:"ttps"`
	Vulnerabilities []struct {
		ID   string  `json:"id"`
		CVSS float64 `json:"cvss"`
	} `json:"vulnerabilities"`
	Tools            []string `json:"tools"`
	NegotiationChats bool     `json:"negotiationchats"`
	RansomNotes      bool     `json:"ransomnotes"`
	YARA             bool     `json:"yara"`
	IOCs             bool     `json:"iocs"`
}

func (c *Client) GetGroup(name string) (*GroupDetail, error) {
	var out GroupDetail
	err := c.doRequest("GET", "groups/"+name, nil, &out)
	return &out, err
}

type Victim struct {
	ID          string `json:"id"`
	Victim      string `json:"victim"`
	Group       string `json:"group"`
	Country     string `json:"country"`
	Sector      string `json:"sector"`
	AttackDate  string `json:"attackdate"`
	Discovered  string `json:"discovered"`
	Website     string `json:"website"`
	Screenshot  string `json:"screenshot"`
	Infostealer string `json:"infostealer"`
	Press       string `json:"press"`
	Permalink   string `json:"permalink"`
}

func (c *Client) GetRecentVictims(order string) ([]Victim, error) {
	params := url.Values{}
	if order != "" {
		params.Set("order", order)
	}
	var out []Victim
	err := c.doRequest("GET", "victims/recent", params, &out)
	return out, err
}

type VictimFilter struct {
	Group   string
	Sector  string
	Country string
	Year    string
	Month   string
	Date    string
	Order   string
}

func (c *Client) ListVictims(filter VictimFilter) ([]Victim, error) {
	params := url.Values{}
	if filter.Group != "" {
		params.Set("group", filter.Group)
	}
	if filter.Sector != "" {
		params.Set("sector", filter.Sector)
	}
	if filter.Country != "" {
		params.Set("country", filter.Country)
	}
	if filter.Year != "" {
		params.Set("year", filter.Year)
	}
	if filter.Month != "" {
		params.Set("month", filter.Month)
	}
	if filter.Date != "" {
		params.Set("date", filter.Date)
	}
	if filter.Order != "" {
		params.Set("order", filter.Order)
	}
	if len(params) == 0 {
		return nil, fmt.Errorf("at least one filter required")
	}
	var out []Victim
	err := c.doRequest("GET", "victims/", params, &out)
	return out, err
}

func (c *Client) SearchVictims(q string, filter VictimFilter) ([]Victim, error) {
	params := url.Values{}
	params.Set("q", q)
	if filter.Group != "" {
		params.Set("group", filter.Group)
	}
	if filter.Sector != "" {
		params.Set("sector", filter.Sector)
	}
	if filter.Country != "" {
		params.Set("country", filter.Country)
	}
	if filter.Year != "" {
		params.Set("year", filter.Year)
	}
	if filter.Month != "" {
		params.Set("month", filter.Month)
	}
	if filter.Date != "" {
		params.Set("date", filter.Date)
	}
	if filter.Order != "" {
		params.Set("order", filter.Order)
	}
	var out []Victim
	err := c.doRequest("GET", "victims/search", params, &out)
	return out, err
}

type VictimDetail struct {
	Victim      string `json:"victim"`
	Group       string `json:"group"`
	Country     string `json:"country"`
	Sector      string `json:"sector"`
	AttackDate  string `json:"attackdate"`
	Discovered  string `json:"discovered"`
	Website     string `json:"website"`
	Screenshot  string `json:"screenshot"`
	Infostealer string `json:"infostealer"`
	Press       string `json:"press"`
	Permalink   string `json:"permalink"`
	Description string `json:"description"`
	Extra       struct {
		PressCoverage []struct {
			Title   string `json:"title"`
			URL     string `json:"url"`
			Source  string `json:"source"`
			Date    string `json:"date"`
		} `json:"press_coverage"`
	} `json:"extra"`
}

func (c *Client) GetVictim(victimID string) (*VictimDetail, error) {
	var out VictimDetail
	err := c.doRequest("GET", "victim/"+victimID, nil, &out)
	return &out, err
}

type IOCGroup struct {
	Group string `json:"group"`
	Types struct {
		MD5    int `json:"md5"`
		SHA256 int `json:"sha256"`
		SHA1   int `json:"sha1"`
		IP     int `json:"ip"`
		Domain int `json:"domain"`
		Email  int `json:"email"`
		BTC    int `json:"btc"`
		XMR    int `json:"xmr"`
	} `json:"types"`
}

func (c *Client) ListIOCGroups(iocType string) ([]IOCGroup, error) {
	params := url.Values{}
	if iocType != "" {
		params.Set("type", iocType)
	}
	var out []IOCGroup
	err := c.doRequest("GET", "iocs", params, &out)
	return out, err
}

type GroupIOCs struct {
	Group  string   `json:"group"`
	MD5    []string `json:"md5,omitempty"`
	SHA256 []string `json:"sha256,omitempty"`
	SHA1   []string `json:"sha1,omitempty"`
	IP     []string `json:"ip,omitempty"`
	Domain []string `json:"domain,omitempty"`
	Email  []string `json:"email,omitempty"`
	BTC    []string `json:"btc,omitempty"`
	XMR    []string `json:"xmr,omitempty"`
}

func (c *Client) GetGroupIOCs(group string, iocType string) (*GroupIOCs, error) {
	params := url.Values{}
	if iocType != "" {
		params.Set("type", iocType)
	}
	var out GroupIOCs
	err := c.doRequest("GET", "iocs/"+group, params, &out)
	return &out, err
}

type NegotiationGroup struct {
	Group string `json:"group"`
	Chats int    `json:"chats"`
}

func (c *Client) ListNegotiationGroups() ([]NegotiationGroup, error) {
	var out []NegotiationGroup
	err := c.doRequest("GET", "negotiations", nil, &out)
	return out, err
}

type NegotiationChat struct {
	ID               string `json:"id"`
	Messages         int    `json:"messages"`
	InitialRansom    string `json:"initial_ransom"`
	NegotiatedRansom string `json:"negotiated_ransom"`
	Paid             bool   `json:"paid"`
}

func (c *Client) ListNegotiationChats(group string) ([]NegotiationChat, error) {
	var out []NegotiationChat
	err := c.doRequest("GET", "negotiations/"+group, nil, &out)
	return out, err
}

type NegotiationChatDetail struct {
	ID               string `json:"id"`
	Messages         []struct {
		Sender    string    `json:"sender"`
		Timestamp time.Time `json:"timestamp"`
		Content   string    `json:"content"`
	} `json:"messages"`
	InitialRansom    string `json:"initial_ransom"`
	NegotiatedRansom string `json:"negotiated_ransom"`
	Paid             bool   `json:"paid"`
}

func (c *Client) GetNegotiationChat(group, chatID string) (*NegotiationChatDetail, error) {
	var out NegotiationChatDetail
	err := c.doRequest("GET", "negotiations/"+group+"/"+chatID, nil, &out)
	return &out, err
}

type RansomNoteGroup struct {
	Group string `json:"group"`
	Notes int    `json:"notes"`
}

func (c *Client) ListRansomNoteGroups() ([]RansomNoteGroup, error) {
	var out []RansomNoteGroup
	err := c.doRequest("GET", "ransomnotes", nil, &out)
	return out, err
}

func (c *Client) ListRansomNotes(group string) ([]string, error) {
	var out []string
	err := c.doRequest("GET", "ransomnotes/"+group, nil, &out)
	return out, err
}

type RansomNote struct {
	Extension string `json:"extension"`
	Content   string `json:"content"`
}

func (c *Client) GetRansomNote(group, noteName string) (*RansomNote, error) {
	var out RansomNote
	err := c.doRequest("GET", "ransomnotes/"+group+"/"+noteName, nil, &out)
	return &out, err
}

type YARAGroup struct {
	Group string `json:"group"`
	Rules int    `json:"rules"`
}

func (c *Client) ListYARAGroups() ([]YARAGroup, error) {
	var out []YARAGroup
	err := c.doRequest("GET", "yara", nil, &out)
	return out, err
}

type YARARule struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`
}

func (c *Client) GetYARARules(group string) ([]YARARule, error) {
	var out []YARARule
	err := c.doRequest("GET", "yara/"+group, nil, &out)
	return out, err
}

type PressEntry struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	URL         string `json:"url"`
	Source      string `json:"source"`
	Date        string `json:"date"`
	Country     string `json:"country"`
	Infostealer string `json:"infostealer"`
	Ransomware  *struct {
		Victim  string `json:"victim"`
		Group   string `json:"group"`
		Website string `json:"website"`
	} `json:"ransomware,omitempty"`
}

func (c *Client) ListPressEntries(year, month, country string) ([]PressEntry, error) {
	params := url.Values{}
	if year != "" {
		params.Set("year", year)
	}
	if month != "" {
		params.Set("month", month)
	}
	if country != "" {
		params.Set("country", country)
	}
	var out []PressEntry
	err := c.doRequest("GET", "press/all", params, &out)
	return out, err
}

func (c *Client) GetRecentPressEntries(country string) ([]PressEntry, error) {
	params := url.Values{}
	if country != "" {
		params.Set("country", country)
	}
	var out []PressEntry
	err := c.doRequest("GET", "press/recent", params, &out)
	return out, err
}

type CSIRTContact struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	URL         string `json:"url"`
	CountryCode string `json:"country_code"`
}

func (c *Client) GetCSIRTContacts(country string) ([]CSIRTContact, error) {
	var out []CSIRTContact
	err := c.doRequest("GET", "csirt/"+country, nil, &out)
	return out, err
}

type SECFiling struct {
	ID      string `json:"id"`
	Company string `json:"company"`
	Ticker  string `json:"ticker"`
	CIK     string `json:"cik"`
	Title   string `json:"title"`
	Date    string `json:"date"`
	Item105 bool   `json:"item105"`
	Item801 bool   `json:"item801"`
	URL     string `json:"url"`
}

func (c *Client) GetSECFilings(ticker, cik, year, month string, item105, item801 bool) ([]SECFiling, error) {
	params := url.Values{}
	if ticker != "" {
		params.Set("ticker", ticker)
	}
	if cik != "" {
		params.Set("cik", cik)
	}
	if year != "" {
		params.Set("year", year)
	}
	if month != "" {
		params.Set("month", month)
	}
	if item105 {
		params.Set("item105", "true")
	}
	if item801 {
		params.Set("item801", "true")
	}
	var out []SECFiling
	err := c.doRequest("GET", "8k", params, &out)
	return out, err
}

type Sector struct {
	Sector string `json:"sector"`
	Count  int    `json:"count"`
}

func (c *Client) ListSectors() ([]Sector, error) {
	var out []Sector
	err := c.doRequest("GET", "listsectors", nil, &out)
	return out, err
}

type Stats struct {
	TotalVictims   int    `json:"total_victims"`
	TotalGroups    int    `json:"total_groups"`
	TotalPress     int    `json:"total_press"`
	LastDiscovered string `json:"last_discovered"`
}

func (c *Client) GetStats() (*Stats, error) {
	var out Stats
	err := c.doRequest("GET", "stats", nil, &out)
	return &out, err
}

type ValidationResponse struct {
	Valid    bool   `json:"valid"`
	ClientID string `json:"client_id"`
}

func (c *Client) ValidateKey() (*ValidationResponse, error) {
	var out ValidationResponse
	err := c.doRequest("GET", "validate", nil, &out)
	return &out, err
}
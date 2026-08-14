package ransomware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultBaseURL   = "https://api-pro.ransomware.live/"
	DefaultTimeout   = 30 * time.Second
	DefaultUserAgent = "ransomware-live-go/2.0"

	maxResponseBytes = 64 << 20
	maxErrorBodyLen  = 500
)

type APIError struct {
	Method     string
	Path       string
	StatusCode int
	Status     string
	Body       string
}

type Client struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
	userAgent  string
}

type Option func(*Client)

type Location struct {
	Available bool   `json:"available"`
	Enabled   bool   `json:"enabled"`
	FQDN      string `json:"fqdn"`
	Slug      string `json:"slug"`
	Title     string `json:"title"`
	Type      string `json:"type"`
}

type LocationList []Location

type Technique struct {
	ID      string `json:"technique_id"`
	Name    string `json:"technique_name"`
	Details string `json:"technique_details"`
}

type TTP struct {
	TacticID         string      `json:"tactic_id"`
	TacticName       string      `json:"tactic_name"`
	Techniques       []Technique `json:"techniques"`
	TechniqueID      string      `json:"technique_id"`
	TechniqueName    string      `json:"technique_name"`
	TechniqueDetails string      `json:"technique_details"`
}

type TTPList []TTP

type GroupSummary struct {
	Group   string  `json:"group"`
	AltName *string `json:"altname"`
	Victims int     `json:"victims"`
}

type Vulnerability struct {
	ID   string  `json:"id"`
	CVSS float64 `json:"cvss"`
}

type VulnerabilityList []Vulnerability

type GroupDetail struct {
	Group            string            `json:"group"`
	AltName          *string           `json:"altname"`
	Description      string            `json:"description"`
	Victims          int               `json:"victims"`
	FirstSeen        string            `json:"firstseen"`
	LastSeen         string            `json:"lastseen"`
	Locations        LocationList      `json:"locations"`
	TTPs             TTPList           `json:"ttps"`
	Vulnerabilities  VulnerabilityList `json:"vulnerabilities"`
	Tools            []string          `json:"tools"`
	HasNegotiations  bool              `json:"has_negotiations"`
	NegotiationCount int               `json:"negotiation_count"`
	HasRansomNote    bool              `json:"has_ransomnote"`
	RansomNotesCount int               `json:"ransomnotes_count"`
	HasYARA          bool              `json:"has_yara"`
	YARACount        int               `json:"yara_count"`
	HasIOCs          bool              `json:"has_iocs"`
	IOCCount         int               `json:"iocs_count"`
	NegotiationChats bool              `json:"negotiationchats,omitempty"` // legacy alias
	RansomNotes      bool              `json:"ransomnotes,omitempty"`      // legacy alias
	YARA             bool              `json:"yara,omitempty"`             // legacy alias
	IOCs             bool              `json:"iocs,omitempty"`             // legacy alias
}

type Victim struct {
	ID          string `json:"id"`
	Victim      string `json:"victim"`
	Group       string `json:"group"`
	Country     string `json:"country"`
	Activity    string `json:"activity"`
	Sector      string `json:"sector"`
	AttackDate  string `json:"attackdate"`
	Discovered  string `json:"discovered"`
	Website     string `json:"website"`
	Domain      string `json:"domain"`
	Screenshot  string `json:"screenshot"`
	Infostealer string `json:"infostealer"`
	Press       string `json:"press"`
	Permalink   string `json:"permalink"`
	URL         string `json:"url"`
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

type VictimDetail struct {
	ID          string `json:"id"`
	Victim      string `json:"victim"`
	Group       string `json:"group"`
	Country     string `json:"country"`
	Activity    string `json:"activity"`
	Sector      string `json:"sector"`
	AttackDate  string `json:"attackdate"`
	Discovered  string `json:"discovered"`
	Website     string `json:"website"`
	Domain      string `json:"domain"`
	Screenshot  string `json:"screenshot"`
	Infostealer string `json:"infostealer"`
	Press       string `json:"press"`
	Permalink   string `json:"permalink"`
	URL         string `json:"url"`
	Description string `json:"description"`
	Extra       struct {
		PressCoverage []struct {
			Title  string `json:"title"`
			URL    string `json:"url"`
			Source string `json:"source"`
			Date   string `json:"date"`
		} `json:"press_coverage"`
	} `json:"extra"`
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
		URL    int `json:"url"`
		BTC    int `json:"btc"`
		XMR    int `json:"xmr"`
	} `json:"types"`
}

type GroupIOCs struct {
	Group  string   `json:"group"`
	MD5    []string `json:"md5,omitempty"`
	SHA256 []string `json:"sha256,omitempty"`
	SHA1   []string `json:"sha1,omitempty"`
	IP     []string `json:"ip,omitempty"`
	Domain []string `json:"domain,omitempty"`
	Email  []string `json:"email,omitempty"`
	URL    []string `json:"url,omitempty"`
	BTC    []string `json:"btc,omitempty"`
	XMR    []string `json:"xmr,omitempty"`
}

type NegotiationGroup struct {
	Group string `json:"group"`
	Chats int    `json:"chats"`
}

type NegotiationChat struct {
	ID               string  `json:"id"`
	MessageCount     int     `json:"message_count"`
	InitialRansom    string  `json:"initialransom"`
	NegotiatedRansom *string `json:"negotiatedransom"`
	Paid             bool    `json:"paid"`
}

type NegotiationMessage struct {
	Sender    string `json:"sender"`
	Timestamp string `json:"timestamp"`
	Content   string `json:"content"`
}

type NegotiationChatDetail struct {
	ID               string               `json:"id"`
	MessageCount     int                  `json:"message_count"`
	Messages         []NegotiationMessage `json:"messages"`
	InitialRansom    string               `json:"initialransom"`
	NegotiatedRansom *string              `json:"negotiatedransom"`
	Paid             bool                 `json:"paid"`
}

type RansomNoteGroup struct {
	Group string `json:"group"`
	Notes int    `json:"notes"`
}

type RansomNote struct {
	Extension string `json:"extension"`
	Content   string `json:"content"`
}

type YARAGroup struct {
	Group string `json:"group"`
	Rules int    `json:"rules"`
}

type YARARule struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`
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

type CSIRTContact struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	URL         string `json:"url"`
	CountryCode string `json:"country_code"`
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

type Sector struct {
	Sector string `json:"sector"`
	Count  int    `json:"count"`
}

type StatsBreakdown struct {
	Victims int `json:"victims"`
	Groups  int `json:"groups"`
	Press   int `json:"press"`
}

type Stats struct {
	Stats      StatsBreakdown `json:"stats"`
	LastUpdate string         `json:"last_update"`
}

type ValidationResponse struct {
	Valid    bool   `json:"valid"`
	ClientID string `json:"client_id"`
}

func (e *APIError) Error() string {
	body := e.Body
	if len(body) > maxErrorBodyLen {
		body = body[:maxErrorBodyLen] + "..."
	}
	return fmt.Sprintf("ransomware.live API %s %s: HTTP %d (%s): %s",
		e.Method, e.Path, e.StatusCode, e.Status, body)
}

func (e *APIError) IsRateLimit() bool { return e.StatusCode == http.StatusTooManyRequests }

func (e *APIError) IsNotFound() bool { return e.StatusCode == http.StatusNotFound }

func (e *APIError) IsUnauthorized() bool {
	return e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden
}

func (e *APIError) IsBadRequest() bool { return e.StatusCode == http.StatusBadRequest }

func AsAPIError(err error) (*APIError, bool) {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr, true
	}
	return nil, false
}

func IsAPIError(err error) bool {
	_, ok := AsAPIError(err)
	return ok
}

func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) { cl.httpClient = c }
}

func WithBaseURL(baseURL string) Option {
	return func(cl *Client) { cl.baseURL = baseURL }
}

func WithUserAgent(userAgent string) Option {
	return func(cl *Client) { cl.userAgent = userAgent }
}

func NewClient(apiKey string, opts ...Option) *Client {
	c := &Client{
		httpClient: &http.Client{Timeout: DefaultTimeout},
		baseURL:    DefaultBaseURL,
		apiKey:     apiKey,
		userAgent:  DefaultUserAgent,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Client) get(ctx context.Context, path string, params url.Values, out any) error {
	reqURL := strings.TrimSuffix(c.baseURL, "/") + "/" + strings.TrimPrefix(path, "/")
	if params != nil && len(params) > 0 {
		reqURL += "?" + params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-KEY", c.apiKey)
	req.Header.Set("Accept", "application/json")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	return decodeResponse(http.MethodGet, reqURL, resp, out)
}

func decodeResponse(method, fullURL string, resp *http.Response, out any) error {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{
			Method:     method,
			Path:       fullURL,
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       string(body),
		}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode %s response from %s: %w", method, fullURL, err)
	}
	return nil
}

func escapePath(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		b.WriteByte('/')
		b.WriteString(url.PathEscape(p))
	}
	return b.String()
}

func (c *Client) ListGroups() ([]GroupSummary, error) {
	return c.ListGroupsWithContext(context.Background())
}

func (c *Client) ListGroupsWithContext(ctx context.Context) ([]GroupSummary, error) {
	var out []GroupSummary
	err := c.get(ctx, "groups", nil, &out)
	return out, err
}

func (l *LocationList) UnmarshalJSON(data []byte) error {
	var objs []Location
	if err := json.Unmarshal(data, &objs); err == nil {
		*l = objs
		return nil
	}
	var strs []string
	if err := json.Unmarshal(data, &strs); err != nil {
		return err
	}
	for _, s := range strs {
		*l = append(*l, Location{Slug: s})
	}
	return nil
}

func (t *TTPList) UnmarshalJSON(data []byte) error {
	var objs []TTP
	if err := json.Unmarshal(data, &objs); err == nil {
		*t = objs
		return nil
	}
	var strs []string
	if err := json.Unmarshal(data, &strs); err != nil {
		return err
	}
	for _, s := range strs {
		*t = append(*t, TTP{TechniqueName: s})
	}
	return nil
}

func (v *VulnerabilityList) UnmarshalJSON(data []byte) error {
	var objs []Vulnerability
	if err := json.Unmarshal(data, &objs); err == nil {
		*v = objs
		return nil
	}
	var strs []string
	if err := json.Unmarshal(data, &strs); err != nil {
		return err
	}
	for _, s := range strs {
		*v = append(*v, Vulnerability{ID: s})
	}
	return nil
}

func (c *Client) GetGroup(name string) (*GroupDetail, error) {
	return c.GetGroupWithContext(context.Background(), name)
}

func (c *Client) GetGroupWithContext(ctx context.Context, name string) (*GroupDetail, error) {
	var out GroupDetail
	err := c.get(ctx, escapePath("groups", name), nil, &out)
	return &out, err
}

func (c *Client) GetGroupCompat(name string) (*GroupDetail, error) {
	return c.GetGroupCompatWithContext(context.Background(), name)
}

func (c *Client) GetGroupCompatWithContext(ctx context.Context, name string) (*GroupDetail, error) {
	var out GroupDetail
	err := c.get(ctx, escapePath("group", name), nil, &out)
	return &out, err
}

func (v *Victim) UnmarshalJSON(data []byte) error {
	type plain Victim
	var raw struct {
		plain
		Activity  string `json:"activity"`
		Sector    string `json:"sector"`
		Website   string `json:"website"`
		Domain    string `json:"domain"`
		Permalink string `json:"permalink"`
		URL       string `json:"url"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*v = Victim(raw.plain)
	activity := raw.Activity
	if activity == "" {
		activity = raw.Sector
	}
	v.Activity = activity
	v.Sector = activity
	website := raw.Website
	if website == "" {
		website = raw.Domain
	}
	v.Website = website
	v.Domain = website
	link := raw.Permalink
	if link == "" {
		link = raw.URL
	}
	v.Permalink = link
	v.URL = link
	return nil
}

func (c *Client) GetRecentVictims(order string) ([]Victim, error) {
	return c.GetRecentVictimsWithContext(context.Background(), order)
}

func (c *Client) GetRecentVictimsWithContext(ctx context.Context, order string) ([]Victim, error) {
	params := url.Values{}
	if order != "" {
		params.Set("order", order)
	}
	var out []Victim
	err := c.get(ctx, "victims/recent", params, &out)
	return out, err
}

func (c *Client) ListVictims(filter VictimFilter) ([]Victim, error) {
	return c.ListVictimsWithContext(context.Background(), filter)
}

func (c *Client) ListVictimsWithContext(ctx context.Context, filter VictimFilter) ([]Victim, error) {
	if err := validateVictimFilter(filter); err != nil {
		return nil, err
	}
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
	var out []Victim
	err := c.get(ctx, "victims/", params, &out)
	return out, err
}

func validateVictimFilter(filter VictimFilter) error {
	if filter.Group == "" && filter.Sector == "" && filter.Country == "" &&
		filter.Year == "" && filter.Month == "" && filter.Date == "" && filter.Order == "" {
		return errors.New("ransomware: at least one victim filter is required")
	}
	if filter.Year != "" && filter.Month == "" {
		return errors.New("ransomware: the year filter must be combined with month")
	}
	if filter.Month != "" && filter.Year == "" {
		return errors.New("ransomware: the month filter requires year")
	}
	return nil
}

func (c *Client) SearchVictims(q string, filter VictimFilter) ([]Victim, error) {
	return c.SearchVictimsWithContext(context.Background(), q, filter)
}

func (c *Client) SearchVictimsWithContext(ctx context.Context, q string, filter VictimFilter) ([]Victim, error) {
	if q == "" {
		return nil, errors.New("ransomware: search query is required")
	}
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
	if filter.Order != "" {
		params.Set("order", filter.Order)
	}
	var out []Victim
	err := c.get(ctx, "victims/search", params, &out)
	return out, err
}

// UnmarshalJSON normalises the alternate field names used across API
// versions (see Victim).
func (v *VictimDetail) UnmarshalJSON(data []byte) error {
	type plain VictimDetail
	var raw struct {
		plain
		Activity  string `json:"activity"`
		Sector    string `json:"sector"`
		Website   string `json:"website"`
		Domain    string `json:"domain"`
		Permalink string `json:"permalink"`
		URL       string `json:"url"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*v = VictimDetail(raw.plain)
	activity := raw.Activity
	if activity == "" {
		activity = raw.Sector
	}
	v.Activity = activity
	v.Sector = activity
	website := raw.Website
	if website == "" {
		website = raw.Domain
	}
	v.Website = website
	v.Domain = website
	link := raw.Permalink
	if link == "" {
		link = raw.URL
	}
	v.Permalink = link
	v.URL = link
	return nil
}

func (c *Client) GetVictim(victimID string) (*VictimDetail, error) {
	return c.GetVictimWithContext(context.Background(), victimID)
}

func (c *Client) GetVictimWithContext(ctx context.Context, victimID string) (*VictimDetail, error) {
	var out VictimDetail
	err := c.get(ctx, escapePath("victim", victimID), nil, &out)
	return &out, err
}

func (c *Client) ListIOCGroups(iocType string) ([]IOCGroup, error) {
	return c.ListIOCGroupsWithContext(context.Background(), iocType)
}

func (c *Client) ListIOCGroupsWithContext(ctx context.Context, iocType string) ([]IOCGroup, error) {
	params := url.Values{}
	if iocType != "" {
		params.Set("type", iocType)
	}
	var out []IOCGroup
	err := c.get(ctx, "iocs", params, &out)
	return out, err
}

func (c *Client) GetGroupIOCs(group, iocType string) (*GroupIOCs, error) {
	return c.GetGroupIOCsWithContext(context.Background(), group, iocType)
}

func (c *Client) GetGroupIOCsWithContext(ctx context.Context, group, iocType string) (*GroupIOCs, error) {
	params := url.Values{}
	if iocType != "" {
		params.Set("type", iocType)
	}
	var out GroupIOCs
	err := c.get(ctx, escapePath("iocs", group), params, &out)
	return &out, err
}

func (c *Client) ListNegotiationGroups() ([]NegotiationGroup, error) {
	return c.ListNegotiationGroupsWithContext(context.Background())
}

func (c *Client) ListNegotiationGroupsWithContext(ctx context.Context) ([]NegotiationGroup, error) {
	var out []NegotiationGroup
	err := c.get(ctx, "negotiations", nil, &out)
	return out, err
}

func (n *NegotiationChat) UnmarshalJSON(data []byte) error {
	type plain NegotiationChat
	var raw struct {
		plain
		Messages               int     `json:"messages"`
		InitialRansomLegacy    string  `json:"initial_ransom"`
		NegotiatedRansomLegacy *string `json:"negotiated_ransom"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*n = NegotiationChat(raw.plain)
	if n.MessageCount == 0 {
		n.MessageCount = raw.Messages
	}
	if n.InitialRansom == "" {
		n.InitialRansom = raw.InitialRansomLegacy
	}
	if n.NegotiatedRansom == nil {
		n.NegotiatedRansom = raw.NegotiatedRansomLegacy
	}
	return nil
}

func (c *Client) ListNegotiationChats(group string) ([]NegotiationChat, error) {
	return c.ListNegotiationChatsWithContext(context.Background(), group)
}

func (c *Client) ListNegotiationChatsWithContext(ctx context.Context, group string) ([]NegotiationChat, error) {
	var out []NegotiationChat
	err := c.get(ctx, escapePath("negotiations", group), nil, &out)
	return out, err
}

// UnmarshalJSON normalises legacy field names into the documented ones.
func (n *NegotiationChatDetail) UnmarshalJSON(data []byte) error {
	type plain NegotiationChatDetail
	var raw struct {
		plain
		InitialRansomLegacy    string  `json:"initial_ransom"`
		NegotiatedRansomLegacy *string `json:"negotiated_ransom"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*n = NegotiationChatDetail(raw.plain)
	if n.InitialRansom == "" {
		n.InitialRansom = raw.InitialRansomLegacy
	}
	if n.NegotiatedRansom == nil {
		n.NegotiatedRansom = raw.NegotiatedRansomLegacy
	}
	return nil
}

func (c *Client) GetNegotiationChat(group, chatID string) (*NegotiationChatDetail, error) {
	return c.GetNegotiationChatWithContext(context.Background(), group, chatID)
}

func (c *Client) GetNegotiationChatWithContext(ctx context.Context, group, chatID string) (*NegotiationChatDetail, error) {
	var out NegotiationChatDetail
	err := c.get(ctx, escapePath("negotiations", group, chatID), nil, &out)
	return &out, err
}

func (c *Client) ListRansomNoteGroups() ([]RansomNoteGroup, error) {
	return c.ListRansomNoteGroupsWithContext(context.Background())
}

func (c *Client) ListRansomNoteGroupsWithContext(ctx context.Context) ([]RansomNoteGroup, error) {
	var out []RansomNoteGroup
	err := c.get(ctx, "ransomnotes", nil, &out)
	return out, err
}

func (c *Client) ListRansomNotes(group string) ([]string, error) {
	return c.ListRansomNotesWithContext(context.Background(), group)
}

func (c *Client) ListRansomNotesWithContext(ctx context.Context, group string) ([]string, error) {
	var out []string
	err := c.get(ctx, escapePath("ransomnotes", group), nil, &out)
	return out, err
}

func (c *Client) GetRansomNote(group, noteName string) (*RansomNote, error) {
	return c.GetRansomNoteWithContext(context.Background(), group, noteName)
}

func (c *Client) GetRansomNoteWithContext(ctx context.Context, group, noteName string) (*RansomNote, error) {
	var out RansomNote
	err := c.get(ctx, escapePath("ransomnotes", group, noteName), nil, &out)
	return &out, err
}

func (c *Client) ListYARAGroups() ([]YARAGroup, error) {
	return c.ListYARAGroupsWithContext(context.Background())
}

func (c *Client) ListYARAGroupsWithContext(ctx context.Context) ([]YARAGroup, error) {
	var out []YARAGroup
	err := c.get(ctx, "yara", nil, &out)
	return out, err
}

func (c *Client) GetYARARules(group string) ([]YARARule, error) {
	return c.GetYARARulesWithContext(context.Background(), group)
}

func (c *Client) GetYARARulesWithContext(ctx context.Context, group string) ([]YARARule, error) {
	var out []YARARule
	err := c.get(ctx, escapePath("yara", group), nil, &out)
	return out, err
}

func (c *Client) ListPressEntries(year, month, country string) ([]PressEntry, error) {
	return c.ListPressEntriesWithContext(context.Background(), year, month, country)
}

func (c *Client) ListPressEntriesWithContext(ctx context.Context, year, month, country string) ([]PressEntry, error) {
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
	err := c.get(ctx, "press/all", params, &out)
	return out, err
}

func (c *Client) GetRecentPressEntries(country string) ([]PressEntry, error) {
	return c.GetRecentPressEntriesWithContext(context.Background(), country)
}

func (c *Client) GetRecentPressEntriesWithContext(ctx context.Context, country string) ([]PressEntry, error) {
	params := url.Values{}
	if country != "" {
		params.Set("country", country)
	}
	var out []PressEntry
	err := c.get(ctx, "press/recent", params, &out)
	return out, err
}

func (c *Client) GetCSIRTContacts(country string) ([]CSIRTContact, error) {
	return c.GetCSIRTContactsWithContext(context.Background(), country)
}

func (c *Client) GetCSIRTContactsWithContext(ctx context.Context, country string) ([]CSIRTContact, error) {
	var out []CSIRTContact
	err := c.get(ctx, escapePath("csirt", country), nil, &out)
	return out, err
}

func (c *Client) GetSECFilings(ticker, cik, year, month string, item105, item801 bool) ([]SECFiling, error) {
	return c.GetSECFilingsWithContext(context.Background(), ticker, cik, year, month, item105, item801)
}

func (c *Client) GetSECFilingsWithContext(ctx context.Context, ticker, cik, year, month string, item105, item801 bool) ([]SECFiling, error) {
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
	params.Set("item105", strconv.FormatBool(item105))
	params.Set("item801", strconv.FormatBool(item801))
	var out []SECFiling
	err := c.get(ctx, "8k", params, &out)
	return out, err
}

func (c *Client) ListSectors() ([]Sector, error) {
	return c.ListSectorsWithContext(context.Background())
}

func (c *Client) ListSectorsWithContext(ctx context.Context) ([]Sector, error) {
	var out []Sector
	err := c.get(ctx, "listsectors", nil, &out)
	return out, err
}

func (s *Stats) UnmarshalJSON(data []byte) error {
	var raw struct {
		Stats          *StatsBreakdown `json:"stats"`
		LastUpdate     string          `json:"last_update"`
		TotalVictims   int             `json:"total_victims"`
		TotalGroups    int             `json:"total_groups"`
		TotalPress     int             `json:"total_press"`
		LastDiscovered string          `json:"last_discovered"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.Stats != nil {
		s.Stats = *raw.Stats
	} else {
		s.Stats = StatsBreakdown{
			Victims: raw.TotalVictims,
			Groups:  raw.TotalGroups,
			Press:   raw.TotalPress,
		}
	}
	s.LastUpdate = raw.LastUpdate
	if s.LastUpdate == "" {
		s.LastUpdate = raw.LastDiscovered
	}
	return nil
}

func (c *Client) GetStats() (*Stats, error) {
	return c.GetStatsWithContext(context.Background())
}

func (c *Client) GetStatsWithContext(ctx context.Context) (*Stats, error) {
	var out Stats
	err := c.get(ctx, "stats", nil, &out)
	return &out, err
}

func (c *Client) ValidateKey() (*ValidationResponse, error) {
	return c.ValidateKeyWithContext(context.Background())
}

func (c *Client) ValidateKeyWithContext(ctx context.Context) (*ValidationResponse, error) {
	var out ValidationResponse
	err := c.get(ctx, "validate", nil, &out)
	return &out, err
}

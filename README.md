# Ransomware.live - Go Client

A Go client for the authenticated Ransomware.live **PRO API**
(`https://api-pro.ransomware.live`), a comprehensive threat intelligence
feed tracking ransomware groups, victims, indicators of compromise (IoCs),
negotiation chats, ransom notes, YARA rules, SEC 8-K filings and more.

The implementation follows the official
[PRO API documentation](https://api-pro.ransomware.live/docs).

---

## Installation

```bash
go get github.com/dabumana/ransomware-live-go
```

Replace with your actual module path if publishing.

## Quick start

All endpoints require an `X-API-KEY` header. Get a free key at
[ransomware.live/my](https://www.ransomware.live/my).

```go
package main

import (
    "fmt"
    "log"
    ransomware "github.com/dabumana/ransomware-live-go"
)

func main() {
    client := ransomware.NewClient("YOUR_API_KEY")

    // Check that the key is valid before doing anything else.
    validation, err := client.ValidateKey()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("valid key for client %q\n", validation.ClientID)

    // Get recent victims.
    victims, err := client.GetRecentVictims("")
    if err != nil {
        log.Fatal(err)
    }
    for _, v := range victims {
        fmt.Printf("%s - %s (%s)\n", v.Victim, v.Group, v.Country)
    }
}
```

## Client configuration

```go
customClient := &http.Client{Timeout: 30 * time.Second}
client := ransomware.NewClient(
    "api-key",
    ransomware.WithHTTPClient(customClient), // custom transport/timeout
    ransomware.WithBaseURL("https://custom-api.example.com"), // override base URL (testing/mirrors)
    ransomware.WithUserAgent("my-app/1.0"),
)
```

Defaults: 30 second timeout, `User-Agent: ransomware-live-go/2.0`.

## Authentication and rate limits

* All endpoints require the `X-API-KEY` header; the client sets it
  automatically on every request.
* Rate limit: 500,000 requests per month per key. Requests beyond the quota
  return HTTP 429.
* Validate a key before heavy usage with `ValidateKey()`.

## Error handling

Non-2xx responses return an `*APIError`. Use `AsAPIError` to unwrap it and the
`Is*` helpers to react programmatically:

```go
victims, err := client.GetRecentVictims("")
if err != nil {
    if apiErr, ok := ransomware.AsAPIError(err); ok {
        switch {
        case apiErr.IsRateLimit():
            fmt.Println("rate limited (429)")
        case apiErr.IsUnauthorized():
            fmt.Println("invalid or missing API key (401/403)")
        case apiErr.IsNotFound():
            fmt.Println("resource not found (404)")
        case apiErr.IsBadRequest():
            fmt.Println("bad parameters (400)")
        }
    }
    log.Fatal(err)
}
```

`APIError` exposes `StatusCode`, `Status`, `Body`, `Method` and `Path`.
Transport failures and JSON decode errors are returned as regular Go errors.

## Context support

Every method has a `WithContext` variant that accepts a `context.Context`,
enabling cancellation and deadlines:

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

victims, err := client.GetRecentVictimsWithContext(ctx, "discovered")
```

## API methods

| Method | Endpoint | Description |
|--------|----------|-------------|
| `ListGroups()` | `GET /groups` | All tracked groups with victim counts and alternate names. |
| `GetGroup(name)` | `GET /groups/{groupname}` | Full group intelligence: description, victims, first/last seen, locations, TTPs, vulnerabilities (CVEs + CVSS), tools, negotiation/ransomnote/YARA/IOC availability and counts. |
| `GetGroupCompat(name)` | `GET /group/{groupname}` | Same record via the legacy single-slash endpoint. |
| `GetRecentVictims(order)` | `GET /victims/recent` | The 100 most recent victims; `order` = `discovered` (default) or `attacked`. |
| `ListVictims(filter)` | `GET /victims/` | Filtered victims; at least one filter required, `year` and `month` must be used together. |
| `SearchVictims(q, filter)` | `GET /victims/search` | Full-text search over victim names/domains with `group`, `sector`, `country`, `order` filters. |
| `GetVictim(victimID)` | `GET /victim/{victim_id}` | Enriched single-victim details (id = Base64 of `post_title@group_name`). |
| `ListIOCGroups(iocType)` | `GET /iocs` | Groups with IOCs and per-type counts (`md5`, `sha256`, `sha1`, `ip`, `domain`, `email`, `url`, `btc`, `xmr`). |
| `GetGroupIOCs(group, iocType)` | `GET /iocs/{group}` | All IOCs for a group, optionally one type. |
| `ListNegotiationGroups()` | `GET /negotiations` | Groups with leaked negotiation chats and chat counts. |
| `ListNegotiationChats(group)` | `GET /negotiations/{group}` | Chat metadata: id, message count, initial/negotiated ransom, paid status. |
| `GetNegotiationChat(group, chatID)` | `GET /negotiations/{group}/{chat_id}` | Full message thread and ransom metadata. |
| `ListRansomNoteGroups()` | `GET /ransomnotes` | Groups with ransom notes on file. |
| `ListRansomNotes(group)` | `GET /ransomnotes/{group}` | Ransom note identifiers for a group. |
| `GetRansomNote(group, noteName)` | `GET /ransomnotes/{group}/{note_name}` | Full ransom note text (`.txt`/`.html`/`.md`). |
| `ListYARAGroups()` | `GET /yara` | Groups with YARA rules and rule counts. |
| `GetYARARules(group)` | `GET /yara/{group}` | YARA rules (filename + content) for a group. |
| `ListPressEntries(year, month, country)` | `GET /press/all` | All press/cyberattack entries with optional filters, sorted by date desc. |
| `GetRecentPressEntries(country)` | `GET /press/recent` | The 100 most recent press entries, optional country filter. |
| `GetCSIRTContacts(country)` | `GET /csirt/{country}` | CSIRT/CERT contacts; accepts alpha-2 (FR) and alpha-3 (FRA). |
| `GetSECFilings(ticker, cik, year, month, item105, item801)` | `GET /8k` | SEC 8-K cybersecurity filings; item flags always sent explicitly (default both true). |
| `ListSectors()` | `GET /listsectors` | Unique sector values with victim counts. |
| `GetStats()` | `GET /stats` | High-level stats: `Stats.Victims/Groups/Press` + `LastUpdate`. |
| `ValidateKey()` | `GET /validate` | Check whether the configured API key is valid. |

## Data types

### Victims

Victim records populate both the documented `Activity` field and the legacy
`Sector` alias, as well as `Website`/`Domain` and `Permalink`/`URL` pairs, so
either API naming works.

### Groups

`GroupDetail` accepts both structured and flat forms for `Locations`, `TTPs`
and `Vulnerabilities` (objects, or plain URL/technique/CVE strings). The
documented `has_negotiations`/`negotiation_count`/`has_ransomnote`/
`ransomnotes_count` fields are canonical; the earlier boolean aliases
(`negotiationchats`, `ransomnotes`, `yara`, `iocs`) are also populated.

### Negotiation chats

`NegotiationChat` and `NegotiationChatDetail` accept both the documented
field names (`message_count`, `initialransom`, `negotiatedransom`) and the
legacy names (`messages`, `initial_ransom`, `negotiated_ransom`). Message
timestamps are kept as strings because their format varies between groups.

### Statistics

`Stats` accepts both the documented nested shape
(`stats.victims/groups/press`, `last_update`) and the earlier flat shape
(`total_victims/...`, `last_discovered`).

## Filtering

### `VictimFilter`

| Field | Description |
|-------|-------------|
| `Group` | Group name, case-insensitive exact match. |
| `Sector` | Sector/industry, case-insensitive exact match (see `ListSectors`). |
| `Country` | ISO 3166-1 alpha-2 code, uppercase (e.g. `US`). |
| `Year` | 4-digit year. Must be combined with `Month` — `year` alone is rejected. |
| `Month` | 2-digit month (e.g. `06`). Requires `Year`. |
| `Date` | Date field to filter on: `discovered` (default) or `attacked`. |
| `Order` | Sort order: `discovered` (default) or `attacked`. |

`ListVictims` requires at least one filter. `SearchVictims` requires `q` and
only supports `group`, `sector`, `country` and `order` as secondary filters
(per the official documentation).

## Examples

1. Get detailed group intelligence

```go
group, err := client.GetGroup("lockbit3")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Description: %s\n", group.Description)
for _, ttp := range group.TTPs {
    fmt.Printf("TTP: %s\n", ttp.TacticName)
}
for _, vuln := range group.Vulnerabilities {
    fmt.Printf("CVE: %s (CVSS: %.1f)\n", vuln.ID, vuln.CVSS)
}
```

2. Filter victims by group and country

```go
filter := ransomware.VictimFilter{
    Group:   "lockbit",
    Country: "US",
}
victims, err := client.ListVictims(filter)
if err != nil {
    log.Fatal(err)
}
```

3. Get IOCs for a group

```go
iocs, err := client.GetGroupIOCs("lockbit3", "ip")
if err != nil {
    log.Fatal(err)
}
for _, ip := range iocs.IP {
    fmt.Println(ip)
}
```

4. Get a negotiation chat

```go
chats, err := client.ListNegotiationChats("lockbit3")
if err != nil {
    log.Fatal(err)
}
if len(chats) > 0 {
    chat, err := client.GetNegotiationChat("lockbit3", chats[0].ID)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Initial ransom: %s, Paid: %t\n", chat.InitialRansom, chat.Paid)
}
```

5. Get SEC 8-K filings

```go
filings, err := client.GetSECFilings("MSFT", "", "2025", "", true, true)
if err != nil {
    log.Fatal(err)
}
for _, f := range filings {
    fmt.Printf("Filing: %s\n", f.Title)
}
```

## Live tests

The repository ships with an environment-gated live test that exercises the
real API with your key:

```bash
RANSOMWARE_LIVE_API_KEY=your-key go test -run TestLivePRO -count=1 -v .
```

## Important notes

* **Authentication** — all endpoints require an `X-API-KEY` header. Obtain a
  free key from [ransomware.live/my](https://www.ransomware.live/my).
* **Rate limits** — 500,000 requests per month per key.
* **Date fields** — `attackdate` is the estimated attack/publication date;
  `discovered` is when ransomware.live first observed the listing.
* **Country codes** — ISO 3166-1 alpha-2 (2-letter, e.g. `US`, `FR`) unless
  stated otherwise.
* **Pagination** — the API does not expose explicit pagination for all
  endpoints. `/victims/recent` always returns the 100 most recent entries;
  use date-filtered `/victims/` queries for historical data.
* **IOC endpoints** — not rate limited, but fair use applies.
* **Path parameters** — all path values are URL-escaped automatically.

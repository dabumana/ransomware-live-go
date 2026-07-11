# Ransomware.live - Go Client

A Go client for the Ransomware.live API, a comprehensive threat intelligence feed tracking ransomware groups, victims, indicators of compromise (IoCs), negotiation chats, ransom notes, and more. 

---

## Installation

```bash
go get github.com/dabumana/ransomware
```

Replace with your actual module path if publishing.

###  Quick Start

```go
package main

import (
    "fmt"
    "log"
    "github.com/dabumana/ransomware"
)

func main() {
    client := ransomware.NewClient("YOUR_API_KEY")
    
    // Get recent victims
    victims, err := client.GetRecentVictims()
    if err != nil {
        log.Fatal(err)
    }
    for _, v := range victims {
        fmt.Printf("%s - %s (%s)\n", v.Victim, v.Group, v.Country)
    }
}
```

## Authentication

All endpoints require an X-API-KEY header. You must obtain a free API key from ransomware.live/my.

Pass it to NewClient:

```go
client := ransomware.NewClient("your-api-key")
```

Rate Limits: 500,000 requests per month per key. Requests beyond this quota return HTTP 429.

### Client Configuration

You can customise the client with optional Option functions:

### Option Description
* **WithHTTPClient(http.Client)** Use a custom HTTP client (e.g., with proxy).
* **WithBaseURL(string)** Override the base URL (useful for testing).

Example:

```go
customClient := &http.Client{Timeout: 30 * time.Second}
client := ransomware.NewClient(
    "api-key",
    ransomware.WithHTTPClient(customClient),
    ransomware.WithBaseURL("https://custom-api.example.com"),
)
```
## API Methods

### Groups

Method Endpoint Description
ListGroups() ([]GroupSummary, error) GET /groups Returns all tracked ransomware groups with victim counts.
GetGroup(name string) (*GroupDetail, error) GET /groups/{groupname} Returns comprehensive intelligence about a specific ransomware group, including description, victims, firstseen/lastseen, locations (Tor/clearweb URLs), TTPs (MITRE ATT&CK), vulnerabilities (CVEs with CVSS scores), tools, negotiation/ransomnote availability.

### Victims

Method Endpoint Description
GetRecentVictims(order string) ([]Victim, error) GET /victims/recent Returns the 100 most recent active victims, enriched with screenshot, infostealer data, press coverage, and permalink.
ListVictims(filter VictimFilter) ([]Victim, error) GET /victims/ Returns victims matching the provided filters (at least one filter is required).
SearchVictims(q string, filter VictimFilter) ([]Victim, error) GET /victims/search Full‑text search across victim names and website domains, with optional secondary filters.
GetVictim(victimID string) (*VictimDetail, error) GET /victim/{victim_id} Returns enriched details for a single victim. The victim_id is a Base64‑encoded string of post_title@group_name (obtainable from the id field in any victim listing).

### Indicators of Compromise (IoCs)

Method Endpoint Description
ListIOCGroups(iocType string) ([]IOCGroup, error) GET /iocs Returns all ransomware groups that have IOCs, with a breakdown of IOC types and counts. Use ?type= to filter groups that have a specific IOC type (e.g. md5, ip, btc).
GetGroupIOCs(group string, iocType string) (*GroupIOCs, error) GET /iocs/{group} Returns all IOCs for a specific ransomware group, organised by type (e.g. md5, ip, domain). Use ?type= to retrieve only one IOC type.

### Negotiation Chats

Method Endpoint Description
ListNegotiationGroups() ([]NegotiationGroup, error) GET /negotiations Lists all ransomware groups that have leaked negotiation chat logs available, with a count of chats per group.
ListNegotiationChats(group string) ([]NegotiationChat, error) GET /negotiations/{group} Returns metadata for all available negotiation chats for a given group (chat ID, message count, initial ransom, negotiated ransom, paid status).
GetNegotiationChat(group, chatID string) (*NegotiationChatDetail, error) GET /negotiations/{group}/{chat_id} Returns the complete message thread and ransom metadata for a specific negotiation chat.

### Ransom Notes

Method Endpoint Description
ListRansomNoteGroups() ([]RansomNoteGroup, error) GET /ransomnotes Lists all ransomware groups that have at least one ransom note on file, with a count of notes per group.
ListRansomNotes(group string) ([]string, error) GET /ransomnotes/{group} Returns the list of ransom note identifiers (filenames without extension) for a group.
GetRansomNote(group, noteName string) (*RansomNote, error) GET /ransomnotes/{group}/{note_name} Returns the full text content of a specific ransom note (supported formats: .txt, .html, .md).

### YARA Rules

Method Endpoint Description
ListYARAGroups() ([]YARAGroup, error) GET /yara Lists all ransomware groups that have associated YARA detection rules, with a count of rule files per group.
GetYARARules(group string) ([]YARARule, error) GET /yara/{group} Returns all YARA rules for a specific ransomware group (filename + full rule content).

### Press / Cyberattack Entries

Method Endpoint Description
ListPressEntries(year, month, country string) ([]PressEntry, error) GET /press/all Returns all tracked cyberattack press entries, enriched with HudsonRock infostealer data and a ransomware link if the victim domain matches a known victim. Results sorted by date descending.
GetRecentPressEntries(country string) ([]PressEntry, error) GET /press/recent Returns the 100 most recent cyberattack press entries, enriched with infostealer data and ransomware link. Optional country filter.

### CSIRT Contacts

Method Endpoint Description
GetCSIRTContacts(country string) ([]CSIRTContact, error) GET /csirt/{country} Returns all CSIRT/CERT contacts for the given country. Accepts both ISO 3166-1 alpha-2 (e.g. FR) and alpha-3 (e.g. FRA) codes.

### SEC Form 8-K Filings

Method Endpoint Description
GetSECFilings(ticker, cik, year, month string, item105, item801 bool) ([]SECFiling, error) GET /8k Returns SEC Form 8‑K filings related to cybersecurity incidents (Item 1.05 – Material Cybersecurity Incidents, mandatory since Dec 2023; Item 8.01 – Other Events).

### Sectors

Method Endpoint Description
ListSectors() ([]Sector, error) GET /listsectors Returns all unique sector/industry values from the victim database, sorted alphabetically, with a count of victims per sector.

### Statistics

Method Endpoint Description
GetStats() (*Stats, error) GET /stats Returns high‑level statistics: total victim count, number of tracked ransomware groups, number of press/cyberattack entries, and the timestamp of the most recently discovered victim.

### Validation

Method Endpoint Description
ValidateKey() (*ValidationResponse, error) GET /validate Checks if the provided X-API-KEY header is valid and returns the associated client identifier.

### Data Types

Common Date and Country Fields

* Date fields – attackdate is the estimated attack/publication date; discovered is when ransomware.live first observed the listing.
* Country codes – Use ISO 3166-1 alpha-2 (2-letter, e.g. US, FR) unless stated otherwise.

### Filtering

VictimFilter

Used with ListVictims and SearchVictims:

Field Type Description
Group string Ransomware group name, case‑insensitive exact match.
Sector string Victim sector/industry, case‑insensitive exact match (use ListSectors to get valid values).
Country string ISO 3166‑1 alpha‑2 country code, uppercase (e.g. US, FR).
Year string 4‑digit year (e.g. 2024).
Month string 2‑digit month, requires Year (e.g. 03).
Date string Which date field to filter on: "discovered" (default) or "attacked".
Order string Sort order for recent victims: "discovered" (default) or "attacked".

Note: ListVictims requires at least one filter to be set.

### Error Handling

The client returns standard Go errors. Common errors:

* HTTP 429 – Rate limit exceeded (500,000 requests/month).
* HTTP 401/403 – Invalid or missing API key.
* HTTP 404 – Resource not found (e.g., invalid group name, victim ID, or chat ID).
* HTTP 400 – Invalid parameters (e.g., missing required fields).

### Examples

1. List All Groups

```go
groups, err := client.ListGroups()
if err != nil {
    log.Fatal(err)
}
for _, g := range groups {
    fmt.Printf("%s: %d victims\n", g.Group, g.Victims)
}
```

2. Get Detailed Group Intelligence

```go
group, err := client.GetGroup("lockbit3")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Description: %s\n", group.Description)
for _, ttp := range group.TTPs {
    fmt.Printf("TTP: %s\n", ttp)
}
for _, vuln := range group.Vulnerabilities {
    fmt.Printf("CVE: %s (CVSS: %.1f)\n", vuln.ID, vuln.CVSS)
}
```

3. Get Recent Victims

```go
victims, err := client.GetRecentVictims("discovered")
if err != nil {
    log.Fatal(err)
}
for _, v := range victims {
    fmt.Printf("%s (%s) - %s\n", v.Victim, v.Group, v.Country)
}
```

4. Filter Victims by Group and Country

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

5. Search Victims by Keyword

```go
victims, err := client.SearchVictims("hospital", ransomware.VictimFilter{Country: "FR"})
if err != nil {
    log.Fatal(err)
}
```

6. Get IOCs for a Group

```go
iocs, err := client.GetGroupIOCs("lockbit3", "ip")
if err != nil {
    log.Fatal(err)
}
for _, ip := range iocs.IPs {
    fmt.Println(ip)
}
```

7. Get Negotiation Chat

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

8. Get Ransom Note Content

```go
notes, err := client.ListRansomNotes("lockbit3")
if err != nil {
    log.Fatal(err)
}
if len(notes) > 0 {
    note, err := client.GetRansomNote("lockbit3", notes[0])
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Format: %s\nContent: %s\n", note.Extension, note.Content)
}
```

9. Get YARA Rules

```go
rules, err := client.GetYARARules("lockbit3")
if err != nil {
    log.Fatal(err)
}
for _, rule := range rules {
    fmt.Printf("Rule: %s\n%s\n", rule.Filename, rule.Content)
}
```

10. Get SEC 8-K Filings

```go
filings, err := client.GetSECFilings("MSFT", "", "2025", "", true, true)
if err != nil {
    log.Fatal(err)
}
for _, f := range filings {
    fmt.Printf("Filing: %s\n", f.Title)
}
```

11. Validate API Key

```go
resp, err := client.ValidateKey()
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Valid key for client: %s\n", resp.ClientID)
```

---

## Important Notes

* Authentication – All endpoints require an X-API-KEY header. Obtain a free key from ransomware.live/my.
* Rate Limits – 500,000 requests per month per key.
* Date Fields – attackdate is the estimated attack/publication date; discovered is when ransomware.live first observed the listing.
* Country Codes – Use ISO 3166-1 alpha-2 (2-letter, e.g. US, FR) unless stated otherwise.
* Pagination – The API does not expose explicit pagination for all endpoints. The /victims/recent endpoint always returns the 100 most recent entries. For historical data, use the filtered /victims/ endpoint with date filters.
* IOC Endpoints – IOC endpoints are not rate‑limited, but fair use applies.
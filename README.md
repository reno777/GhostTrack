# GhostTrack
An OSINT and information gathering tool for IPs, phone numbers, domains, usernames, emails, and images.

> Forked and expanded by [reno777](https://github.com/reno777) — original by [HunxByts](https://github.com/HunxByts)

<img src="https://github.com/reno777/GhostTrack/blob/main/asset/bn.png"/>

---

## Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | **IP Tracker** | Geolocation, ISP, ASN, timezone, and Maps link for any IP |
| 2 | **Show Your IP** | Displays your current public IP address |
| 3 | **Phone Number Tracker** | Carrier, location, number formats, and OSINT search links (Telegram, WhatsApp, Truecaller, Google) |
| 4 | **Username Tracker** | Searches 22 social media platforms for a given username |
| 5 | **WHOIS Lookup** | Registrar, creation/expiry dates, nameservers, and org info for any domain |
| 6 | **DNS Records** | Queries A, AAAA, MX, NS, TXT, CNAME, and SOA records for any domain |
| 7 | **Email Breach Check** | Checks HaveIBeenPwned for known data breaches tied to an email address (requires free API key) |
| 8 | **EXIF Data Extractor** | Pulls GPS coordinates, device make/model, and timestamps from image files |
| 9 | **Reverse IP Lookup** | Lists all domains co-hosted on a given IP address |
| 10 | **URL Expander** | Reveals the full redirect chain and final destination of any shortened URL |

---

## Installation

### Linux (Debian/Ubuntu)
```
sudo apt-get install git python3 python3-pip
```

### Termux
```
pkg install git python3
```

---

## Usage

```
git clone https://github.com/HunxByts/GhostTrack.git
cd GhostTrack
pip3 install -r requirements.txt
python3 GhostTR.py
```

---

## Requirements

- Python 3.7+
- See `requirements.txt` for Python dependencies:
  - `requests`
  - `phonenumbers`
  - `python-whois`
  - `dnspython`
  - `Pillow`

---

## Notes

- **Email Breach Check** requires a free API key from [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key)
- **Reverse IP Lookup** uses the HackerTarget free API (rate limited)
- IP tracking pairs well with [Seeker](https://github.com/thewhiteh4t/seeker) to capture a target's real IP

---

<details>
<summary>Credits</summary>
<strong>Fork maintained by: <a href="https://github.com/reno777">reno777</a></strong><br>
<strong>Original author: <a href="https://github.com/HunxByts">HunxByts</a></strong>
</details>

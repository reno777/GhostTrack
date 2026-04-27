#!/usr/bin/python
# GhostTrack - OSINT Information Gathering Tool
# Forked and expanded by: reno777 (https://github.com/reno777)
# Original author: HunxByts (https://github.com/HunxByts)

# ── IMPORTS ──────────────────────────────────────────────────────────────────

import requests
import time
import os
import phonenumbers
import whois
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from phonenumbers import carrier, geocoder, timezone
from sys import stderr

# ── COLORS ───────────────────────────────────────────────────────────────────

Re = '\033[1;31m'  # red
Gr = '\033[1;32m'  # green
Ye = '\033[1;33m'  # yellow
Wh = '\033[1;37m'  # white

# ── UTILITIES ─────────────────────────────────────────────────────────────────

def is_option(func):
    # Decorator that clears the screen and shows the run banner before each tool
    def wrapper(*args, **kwargs):
        run_banner()
        func(*args, **kwargs)
    return wrapper


# ── TOOLS ─────────────────────────────────────────────────────────────────────

@is_option
def IP_Track():
    # Geolocates an IP and returns ISP, ASN, timezone, and a Maps link
    ip = input(f"{Wh}\n Enter IP target : {Gr}").strip()
    print()
    print(f' {Wh}============= {Gr}SHOW INFORMATION IP ADDRESS {Wh}=============')

    req_api = requests.get(f"https://ipwho.is/{ip}", timeout=10)
    ip_data = req_api.json()

    # API returns success=false for invalid or private IPs
    if not ip_data.get("success", True):
        print(f"{Re} Error: {ip_data.get('message', 'Invalid IP address')}")
        return

    lat = float(ip_data['latitude'])
    lon = float(ip_data['longitude'])

    print(f"{Wh}\n IP target       :{Gr}", ip)
    print(f"{Wh} Type IP         :{Gr}", ip_data["type"])
    print(f"{Wh} Country         :{Gr}", ip_data["country"])
    print(f"{Wh} Country Code    :{Gr}", ip_data["country_code"])
    print(f"{Wh} City            :{Gr}", ip_data["city"])
    print(f"{Wh} Continent       :{Gr}", ip_data["continent"])
    print(f"{Wh} Continent Code  :{Gr}", ip_data["continent_code"])
    print(f"{Wh} Region          :{Gr}", ip_data["region"])
    print(f"{Wh} Region Code     :{Gr}", ip_data["region_code"])
    print(f"{Wh} Latitude        :{Gr}", ip_data["latitude"])
    print(f"{Wh} Longitude       :{Gr}", ip_data["longitude"])
    print(f"{Wh} Maps            :{Gr}", f"https://www.google.com/maps/@{lat},{lon},8z")
    print(f"{Wh} EU              :{Gr}", ip_data["is_eu"])
    print(f"{Wh} Postal          :{Gr}", ip_data["postal"])
    print(f"{Wh} Calling Code    :{Gr}", ip_data["calling_code"])
    print(f"{Wh} Capital         :{Gr}", ip_data["capital"])
    print(f"{Wh} Borders         :{Gr}", ip_data["borders"])
    print(f"{Wh} Country Flag    :{Gr}", ip_data["flag"]["emoji"])
    print(f"{Wh} ASN             :{Gr}", ip_data["connection"]["asn"])
    print(f"{Wh} ORG             :{Gr}", ip_data["connection"]["org"])
    print(f"{Wh} ISP             :{Gr}", ip_data["connection"]["isp"])
    print(f"{Wh} Domain          :{Gr}", ip_data["connection"]["domain"])
    print(f"{Wh} ID              :{Gr}", ip_data["timezone"]["id"])
    print(f"{Wh} ABBR            :{Gr}", ip_data["timezone"]["abbr"])
    print(f"{Wh} DST             :{Gr}", ip_data["timezone"]["is_dst"])
    print(f"{Wh} Offset          :{Gr}", ip_data["timezone"]["offset"])
    print(f"{Wh} UTC             :{Gr}", ip_data["timezone"]["utc"])
    # current_time is not always present in the API response
    print(f"{Wh} Current Time    :{Gr}", ip_data["timezone"].get("current_time", "N/A"))


@is_option
def phoneGW():
    # Parses a phone number and returns carrier, location, formats, and OSINT search links
    User_phone = input(f"\n {Wh}Enter phone number target {Gr}Ex [+6281xxxxxxxxx] {Wh}: {Gr}").strip()
    default_region = "ID"  # fallback region if no country code is provided

    try:
        parsed_number = phonenumbers.parse(User_phone, default_region)
    except phonenumbers.NumberParseException as e:
        print(f"{Re} Invalid phone number: {e}")
        return
    region_code = phonenumbers.region_code_for_number(parsed_number)
    jenis_provider = carrier.name_for_number(parsed_number, "en")
    location = geocoder.description_for_number(parsed_number, "id")
    is_valid_number = phonenumbers.is_valid_number(parsed_number)
    is_possible_number = phonenumbers.is_possible_number(parsed_number)
    formatted_number = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    formatted_number_for_mobile = phonenumbers.format_number_for_mobile_dialing(
        parsed_number, default_region, with_formatting=True
    )
    number_type = phonenumbers.number_type(parsed_number)
    e164 = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
    timezoneF = ', '.join(timezone.time_zones_for_number(parsed_number))

    # Preformat the number variants used in OSINT links
    digits_only = e164.replace('+', '')       # for WhatsApp (wa.me)
    encoded = e164.replace('+', '%2B')        # for Google search URL

    print(f"\n {Wh}========== {Gr}SHOW INFORMATION PHONE NUMBERS {Wh}==========")
    print(f"\n {Wh}Location             :{Gr} {location}")
    print(f" {Wh}Region Code          :{Gr} {region_code}")
    print(f" {Wh}Timezone             :{Gr} {timezoneF}")
    print(f" {Wh}Operator             :{Gr} {jenis_provider}")
    print(f" {Wh}Valid number         :{Gr} {is_valid_number}")
    print(f" {Wh}Possible number      :{Gr} {is_possible_number}")
    print(f" {Wh}International format :{Gr} {formatted_number}")
    print(f" {Wh}Mobile format        :{Gr} {formatted_number_for_mobile}")
    print(f" {Wh}National number      :{Gr} {parsed_number.national_number}")
    print(f" {Wh}E.164 format         :{Gr} {e164}")
    print(f" {Wh}Country code         :{Gr} {parsed_number.country_code}")

    if number_type == phonenumbers.PhoneNumberType.MOBILE:
        print(f" {Wh}Type                 :{Gr} This is a mobile number")
    elif number_type == phonenumbers.PhoneNumberType.FIXED_LINE:
        print(f" {Wh}Type                 :{Gr} This is a fixed-line number")
    else:
        print(f" {Wh}Type                 :{Gr} This is another type of number")

    # Direct platform links for manual OSINT — automated lookup requires paid APIs
    print(f"\n {Wh}========== {Gr}OSINT SEARCH LINKS {Wh}==========")
    print(f" {Wh}[ {Gr}+ {Wh}] Telegram    : {Gr}https://t.me/{e164}")
    print(f" {Wh}[ {Gr}+ {Wh}] WhatsApp    : {Gr}https://wa.me/{digits_only}")
    print(f" {Wh}[ {Gr}+ {Wh}] Truecaller  : {Gr}https://www.truecaller.com/search/{region_code}/{parsed_number.national_number}")
    print(f" {Wh}[ {Gr}+ {Wh}] Google      : {Gr}https://www.google.com/search?q={encoded}")


@is_option
def TrackLu():
    # Checks whether a username exists on social media platforms via HTTP status codes
    # Note: a 200 response indicates the profile URL is reachable, not always that the account exists
    # Requests run in parallel via ThreadPoolExecutor for speed
    username = input(f"\n {Wh}Enter Username : {Gr}").strip()
    social_media = [
        {"url": "https://www.facebook.com/{}", "name": "Facebook"},
        {"url": "https://www.twitter.com/{}", "name": "Twitter"},
        {"url": "https://www.instagram.com/{}", "name": "Instagram"},
        {"url": "https://www.linkedin.com/in/{}", "name": "LinkedIn"},
        {"url": "https://www.github.com/{}", "name": "GitHub"},
        {"url": "https://www.pinterest.com/{}", "name": "Pinterest"},
        {"url": "https://www.tumblr.com/{}", "name": "Tumblr"},
        {"url": "https://www.youtube.com/{}", "name": "Youtube"},
        {"url": "https://soundcloud.com/{}", "name": "SoundCloud"},
        {"url": "https://www.snapchat.com/add/{}", "name": "Snapchat"},
        {"url": "https://www.tiktok.com/@{}", "name": "TikTok"},
        {"url": "https://www.behance.net/{}", "name": "Behance"},
        {"url": "https://www.medium.com/@{}", "name": "Medium"},
        {"url": "https://www.quora.com/profile/{}", "name": "Quora"},
        {"url": "https://www.flickr.com/people/{}", "name": "Flickr"},
        {"url": "https://www.periscope.tv/{}", "name": "Periscope"},
        {"url": "https://www.twitch.tv/{}", "name": "Twitch"},
        {"url": "https://www.dribbble.com/{}", "name": "Dribbble"},
        {"url": "https://www.stumbleupon.com/stumbler/{}", "name": "StumbleUpon"},
        {"url": "https://www.ello.co/{}", "name": "Ello"},
        {"url": "https://www.producthunt.com/@{}", "name": "Product Hunt"},
        {"url": "https://www.telegram.me/{}", "name": "Telegram"},
        {"url": "https://www.weheartit.com/{}", "name": "We Heart It"}
    ]

    def check_site(site):
        url = site['url'].format(username)
        try:
            response = requests.get(url, timeout=10)
            found = response.status_code == 200
        except Exception:
            found = False
        return site['name'], url, found

    print(f"{Ye}\n Checking {len(social_media)} platforms...")
    results = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_site, site): site for site in social_media}
        for future in as_completed(futures):
            name, url, found = future.result()
            results[name] = url if found else f"{Ye}Username not found!"

    print(f"\n {Wh}========== {Gr}SHOW INFORMATION USERNAME {Wh}==========")
    print()
    # Print in original order rather than completion order
    order = [s['name'] for s in social_media]
    for name in order:
        print(f" {Wh}[ {Gr}+ {Wh}] {name} : {Gr}{results[name]}")


@is_option
def showIP():
    # Returns the machine's current public-facing IP via ipify
    try:
        response = requests.get('https://api.ipify.org/', timeout=10)
        Show_IP = response.text
    except Exception as e:
        print(f"{Re} Error retrieving IP: {e}")
        return

    print(f"\n {Wh}========== {Gr}SHOW INFORMATION YOUR IP {Wh}==========")
    print(f"\n {Wh}[{Gr} + {Wh}] Your IP Address : {Gr}{Show_IP}")
    print(f"\n {Wh}==============================================")


@is_option
def whois_lookup():
    # Queries WHOIS for domain registration info: registrar, dates, nameservers, org
    domain = input(f"\n {Wh}Enter domain target {Gr}Ex [example.com] {Wh}: {Gr}").strip()
    print()
    print(f' {Wh}============= {Gr}WHOIS LOOKUP {Wh}=============')
    try:
        w = whois.whois(domain)
    except Exception as e:
        print(f"{Re} Error: {e}")
        return

    def fmt(val):
        # WHOIS fields sometimes return lists (e.g. multiple name servers or dates)
        if isinstance(val, list):
            return ', '.join(str(v) for v in val)
        return str(val) if val else 'N/A'

    print(f"{Wh}\n Domain          :{Gr}", fmt(w.domain_name))
    print(f"{Wh} Registrar       :{Gr}", fmt(w.registrar))
    print(f"{Wh} Created         :{Gr}", fmt(w.creation_date))
    print(f"{Wh} Expires         :{Gr}", fmt(w.expiration_date))
    print(f"{Wh} Updated         :{Gr}", fmt(w.updated_date))
    print(f"{Wh} Name Servers    :{Gr}", fmt(w.name_servers))
    print(f"{Wh} Status          :{Gr}", fmt(w.status))
    print(f"{Wh} Emails          :{Gr}", fmt(w.emails))
    print(f"{Wh} Org             :{Gr}", fmt(w.org))
    print(f"{Wh} Country         :{Gr}", fmt(w.country))


@is_option
def dns_lookup():
    # Queries common DNS record types for a domain; silently skips types with no records
    domain = input(f"\n {Wh}Enter domain target {Gr}Ex [example.com] {Wh}: {Gr}").strip()
    print()
    print(f' {Wh}============= {Gr}DNS RECORDS {Wh}=============')
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    found_any = False
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for rdata in answers:
                print(f"{Wh} {rtype:<6}          :{Gr}", rdata.to_text())
            found_any = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception:
            pass
    if not found_any:
        print(f"{Re} No DNS records found for {domain}")


@is_option
def email_breach():
    # Checks HaveIBeenPwned v3 for known data breaches tied to an email address
    # Requires a free API key from haveibeenpwned.com/API/Key
    email = input(f"\n {Wh}Enter email target {Wh}: {Gr}").strip()
    api_key = input(f" {Wh}Enter HIBP API key (haveibeenpwned.com/API/Key) {Wh}: {Gr}").strip()
    print()
    print(f' {Wh}============= {Gr}EMAIL BREACH CHECK {Wh}=============')
    headers = {
        'hibp-api-key': api_key,
        'user-agent': 'GhostTrack-OSINT'
    }
    try:
        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers=headers,
            timeout=10
        )
        if resp.status_code == 404:
            print(f"{Gr}\n No breaches found for {email}")
            return
        if resp.status_code == 401:
            print(f"{Re} Invalid or missing API key")
            return
        if resp.status_code != 200:
            print(f"{Re} Error: HTTP {resp.status_code}")
            return
        breaches = resp.json()
        print(f"{Re}\n Found in {len(breaches)} breach(es):\n")
        for b in breaches:
            print(f"{Wh} Name            :{Gr}", b.get('Name'))
            print(f"{Wh} Domain          :{Gr}", b.get('Domain'))
            print(f"{Wh} Breach Date     :{Gr}", b.get('BreachDate'))
            print(f"{Wh} Pwn Count       :{Gr}", f"{b.get('PwnCount', 0):,}")
            print(f"{Wh} Data Classes    :{Gr}", ', '.join(b.get('DataClasses', [])))
            print()
    except Exception as e:
        print(f"{Re} Error: {e}")


@is_option
def exif_extract():
    # Reads EXIF metadata from an image — GPS coordinates, device info, timestamps
    path = input(f"\n {Wh}Enter image file path {Wh}: {Gr}").strip()
    print()
    print(f' {Wh}============= {Gr}EXIF DATA {Wh}=============')
    try:
        img = Image.open(path)
        exif_raw = img.getexif()
    except FileNotFoundError:
        print(f"{Re} File not found: {path}")
        return
    except Exception as e:
        print(f"{Re} Error reading image: {e}")
        return

    if not exif_raw:
        print(f"{Ye} No EXIF data found in this image")
        return

    # Map numeric EXIF tag IDs to human-readable names
    exif = {TAGS.get(k, k): v for k, v in exif_raw.items()}

    gps_info = exif.get('GPSInfo')
    if gps_info:
        gps = {GPSTAGS.get(k, k): v for k, v in gps_info.items()}

        def dms_to_dd(dms, ref):
            # Convert degrees/minutes/seconds tuple to decimal degrees
            d, m, s = dms
            dd = float(d) + float(m) / 60 + float(s) / 3600
            return -dd if ref in ('S', 'W') else dd

        try:
            lat = dms_to_dd(gps['GPSLatitude'], gps['GPSLatitudeRef'])
            lon = dms_to_dd(gps['GPSLongitude'], gps['GPSLongitudeRef'])
            print(f"{Wh} GPS Coordinates :{Gr}", f"{lat:.6f}, {lon:.6f}")
            print(f"{Wh} Maps            :{Gr}", f"https://www.google.com/maps/@{lat},{lon},15z")
        except KeyError:
            pass

    for tag in ('Make', 'Model', 'Software', 'DateTime', 'DateTimeOriginal',
                'ExifImageWidth', 'ExifImageHeight', 'Flash', 'FocalLength'):
        val = exif.get(tag)
        if val:
            print(f"{Wh} {tag:<16} :{Gr}", val)


@is_option
def reverse_ip():
    # Finds all domains co-hosted on a given IP via HackerTarget (free, rate limited)
    ip = input(f"\n {Wh}Enter IP target {Wh}: {Gr}").strip()
    print()
    print(f' {Wh}============= {Gr}REVERSE IP LOOKUP {Wh}=============')
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            timeout=10
        )
        if resp.status_code != 200 or 'error' in resp.text.lower():
            print(f"{Re} Error: {resp.text.strip()}")
            return
        domains = resp.text.strip().splitlines()
        if not domains or domains == ['']:
            print(f"{Ye} No domains found hosted on {ip}")
            return
        print(f"{Gr}\n Found {len(domains)} domain(s) on {ip}:\n")
        for domain in domains:
            print(f"{Wh} [ {Gr}+ {Wh}] {Gr}{domain}")
    except Exception as e:
        print(f"{Re} Error: {e}")


@is_option
def url_expander():
    # Follows all redirects and displays the full chain to the final destination
    url = input(f"\n {Wh}Enter shortened URL {Wh}: {Gr}").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    print()
    print(f' {Wh}============= {Gr}URL EXPANDER {Wh}=============')
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
        # Build full chain: each intermediate redirect + final URL
        chain = [r.url for r in resp.history] + [resp.url]
        if len(chain) == 1:
            print(f"{Ye}\n No redirects detected — URL may already be direct")
        else:
            print(f"{Gr}\n Redirect chain ({len(chain) - 1} hop(s)):\n")
            for i, step in enumerate(chain[:-1]):
                print(f"{Wh} [{i + 1}] {Gr}{step}")
        print(f"\n{Wh} Final URL       :{Gr}", resp.url)
        print(f"{Wh} Status Code     :{Gr}", resp.status_code)
        print(f"{Wh} Content Type    :{Gr}", resp.headers.get('Content-Type', 'N/A').split(';')[0])
    except Exception as e:
        print(f"{Re} Error: {e}")


# ── MENU ──────────────────────────────────────────────────────────────────────

options = [
    {'num': 1,  'text': 'IP Tracker',           'func': IP_Track},
    {'num': 2,  'text': 'Show Your IP',          'func': showIP},
    {'num': 3,  'text': 'Phone Number Tracker',  'func': phoneGW},
    {'num': 4,  'text': 'Username Tracker',      'func': TrackLu},
    {'num': 5,  'text': 'WHOIS Lookup',          'func': whois_lookup},
    {'num': 6,  'text': 'DNS Records',           'func': dns_lookup},
    {'num': 7,  'text': 'Email Breach Check',    'func': email_breach},
    {'num': 8,  'text': 'EXIF Data Extractor',   'func': exif_extract},
    {'num': 9,  'text': 'Reverse IP Lookup',     'func': reverse_ip},
    {'num': 10, 'text': 'URL Expander',          'func': url_expander},
    {'num': 0,  'text': 'Exit',                  'func': exit},
]


def clear():
    # Cross-platform terminal clear
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')


def call_option(opt):
    match = next((o for o in options if o['num'] == opt), None)
    if not match:
        raise ValueError('Option not found')
    match['func']()


def execute_option(opt):
    # Runs the selected option and waits for the user to return to the menu
    try:
        call_option(opt)
        input(f'\n{Wh}[ {Gr}+ {Wh}] {Gr}Press enter to continue')
    except ValueError as e:
        print(e)
        time.sleep(2)
    except KeyboardInterrupt:
        print(f'\n{Wh}[ {Re}! {Wh}] {Re}Exit')
        time.sleep(2)
        exit()


def option_text():
    # Builds the formatted menu string from the options list
    text = ''
    for opt in options:
        text += f'{Wh}[ {opt["num"]} ] {Gr}{opt["text"]}\n'
    return text


def option():
    # Renders the main menu banner and option list
    clear()
    stderr.writelines(rf"""
       ________               __      ______                __
      / ____/ /_  ____  _____/ /_    /_  __/________ ______/ /__
     / / __/ __ \/ __ \/ ___/ __/_____/ / / ___/ __ `/ ___/ //_/
    / /_/ / / / / /_/ (__  ) /_/_____/ / / /  / /_/ / /__/ ,<
    \____/_/ /_/\____/____/\__/     /_/ /_/   \__,_/\___/_/|_|

              {Wh}[ + ]  F O R K E D   B Y  R E N O 7 7 7  [ + ]
    """)
    stderr.writelines(f"\n\n\n{option_text()}")


def run_banner():
    # Displays the ghost ASCII art banner before each tool runs
    clear()
    time.sleep(1)
    stderr.writelines(f"""{Wh}
         .-.
       .'   `.          {Wh}--------------------------------
       :g g   :         {Wh}| {Gr}GHOST - TRACKER - OSINT TOOL  {Wh}|
       : o    `.        {Wh}|        {Gr}@github/reno777        {Wh}|
      :         ``.     {Wh}--------------------------------
     :             `.
    :  :         .   `.
    :   :          ` . `.
     `.. :            `. ``;
        `:;             `:'
           :              `.
            `.              `.     .
              `'`'`'`---..,___`;.-'
        """)
    time.sleep(0.5)


def main():
    # Main loop — runs until the user selects Exit or presses Ctrl+C
    while True:
        option()
        try:
            opt = int(input(f"{Wh}\n [ + ] {Gr}Select Option : {Wh}"))
            execute_option(opt)
        except ValueError:
            print(f'\n{Wh}[ {Re}! {Wh}] {Re}Please input number')
            time.sleep(2)
        except KeyboardInterrupt:
            print(f'\n{Wh}[ {Re}! {Wh}] {Re}Exit')
            time.sleep(2)
            exit()


if __name__ == '__main__':
    main()

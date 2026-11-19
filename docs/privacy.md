# Privacy policy

BLACKWALL is a VPN client: it connects your device to servers **you** add, by a
subscription link or by keys. It does not come with servers and has no accounts.

**The developer of BLACKWALL receives nothing from the app.** There is no analytics,
no advertising, no crash reporting and no tracking in it, on any platform.

## What stays on your device

- Your subscription links, server keys, per-application routes and settings. They are
  stored in the app's private folder and are not included in device backups on Android.
- Traffic counters and the connection log, kept only to show them to you.

## What the app sends, and where

- **Your traffic** goes to the VPN server you chose, encrypted by that server's
  protocol (VLESS with REALITY or TLS, Trojan, VMess, Shadowsocks). What the server's
  operator does with it is governed by their policy, not this one.
- **Your subscription link** is requested from the provider that gave it to you, to
  refresh the server list.
- **Name lookups for the server's own address** go to your network's resolver and, when
  it does not answer, to public resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9).
- **Where the server really is**: once a server is in use, the app makes one plain HTTP
  request through it to Cloudflare, `http://cloudflare.com/cdn-cgi/trace`. Cloudflare
  sees the server's address, never yours, and answers with the country it places that
  address in; the app shows that country next to the server and keeps it with the
  server on the device. The request carries no cookies, no user agent and nothing about
  you, and it never leaves without the VPN server. **Settings → Real server country**
  turns it off.
- **A connectivity check**: when the server stops answering, the same request through it
  (and through the reserve servers, one at a time) shows whether it still carries
  traffic.
- **Updates** (desktop only): the app asks GitHub which release is the latest and
  downloads it from there. GitHub sees your IP address, as with any download.

## A report for a bug

**Settings → Report for GitHub** saves a text file with the app's recent log to your
Downloads folder and opens a new issue on GitHub; the app itself sends nothing. Before the
file is written, the app takes out subscription and server links, keys, user ids, e-mail
addresses, your user name in folder paths, and the names and public addresses of servers
and sites (each becomes a meaningless token such as `<host:3fa2c1>.com`). You see the file
and decide whether to attach it.

## Android: why the app is a VPN

On Android the app uses the system's `VpnService` to carry the traffic of your
applications to the server you chose; that is its whole purpose. To apply a different
route to a particular application it asks Android which application owns a connection.
The list of installed applications is read to let you pick them, and never leaves the
device.

The camera is used only when you choose to scan a QR code to add a subscription: the
frames are read on the device to find the code and dropped at once; nothing is stored or
sent. A picture you choose for the same purpose is read the same way. On computers the
same button reads a picture on the clipboard or what is on the screen, on the device,
for the same purpose only.

## Changes and contact

Changes to this policy appear in this file, with the history kept by the repository:
<https://github.com/ANODs/blackwall/commits/main/docs/privacy.md>. Questions:
<https://github.com/ANODs/blackwall/issues>.

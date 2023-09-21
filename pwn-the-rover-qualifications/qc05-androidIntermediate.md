# qc05-androidIntermediate

Last challenge provided is again an ```.apk``` file (```Qualification-1.6-intermediate-release.apk```)

I used [JADX](https://github.com/skylot/jadx) to decompile it and produce the corresponding JAVA source code.

The application structure is the same of the one provided for the [previous challenge](./qc03-androidTrivial.md).

A new implementation of ```Verifier.verifyPassword``` method is provided:

```java
    public static native String checkPasswordByJNI07(String str);

        static {
            System.loadLibrary("native-lib");
        }

        private Verifier() {
        }

        public static boolean verifyPassword(Context context, String str) {
            return "TRUE".equals(checkPasswordByJNI07(str));
        }
```

This time just reading the reversed JAVA source won't be enough since, as we can see from the previous code snippet, the actual password checking logic is performed by a **JNI function**, which is just returning the string "TRUE" if operation is successful.

The Java Native Interface (JNI) allows developers to declare Java methods that are implemented in native code (usually compiled C/C++)

**Android native libraries** are included in APKs as ```.so```, shared object libraries, in the ELF file format.

What we are going to do now is opening the native library (we can find it under ```/Resources/lib/<cpu>/libnative-lib.so``` of JADX project) with [Ghidra](https://ghidra-sre.org/) and try to reverse ```checkPasswordByJNI07``` function.

Many informations can be obtained through the decompiled function:

```c
    jstring Java_org_esa_ptr23_qualification_Verifier_checkPasswordByJNI07
                  (JNIEnv *param_1,JNIEnv *param_2,jstring param_3)
        ...
        jVar4 = (*(*param_1)->GetStringUTFLength)(param_1,param_3);
        uVar3 = (uint)jVar4;
        ...
        if (uVar3 == 0x13) {
            ...
        }
```

The flag's length is probably equal to **0x13 = 19**.

The below reported array is interesting:

```c
  __ptr = (int *)malloc(0x4c);
  *__ptr = 0x50;
  __ptr[1] = 0x55;
  __ptr[2] = 0x54;
  __ptr[3] = 0x7e;
  __ptr[4] = 0x4a;
  __ptr[5] = 0x71;
  __ptr[6] = 0x7f;
  __ptr[7] = 0x54;
  __ptr[8] = 0x6d;
  __ptr[9] = 0x5d;
  __ptr[10] = 0x79;
  __ptr[0xb] = 0x5f;
  __ptr[0xc] = 0x74;
  __ptr[0xd] = 0x72;
  __ptr[0xe] = 0x5b;
  __ptr[0xf] = 0x7e;
  *(undefined8 *)(__ptr + 0x10) = 0x7f0000007f;
  __ptr[0x12] = 0x8f;
```

it is inizialized with 19 bytes elements i.e. number of elements equal to flag length.

The code now reported appears to implemented the core functionalities of the whole function:

```c
  p_Var6 = (*(*param_1)->NewStringUTF)(param_1,"FALSE");
  if (uVar3 == 0x13) {
    pcVar5 = (char *)((long)&local_50 + 1);
    pcVar7 = local_40;
    if ((local_50 & 1) == 0) {
      pcVar7 = pcVar5;
    }
    if (*__ptr == (int)*pcVar7) {
      pcVar7 = local_40;
      if ((local_50 & 1) == 0) {
        pcVar7 = pcVar5;
      }
      if (__ptr[1] == pcVar7[1] + 1) {
        pcVar7 = local_40;
        if ((local_50 & 1) == 0) {
          pcVar7 = pcVar5;
        }
        ...
            if (__ptr[0x11] == pcVar7[0x11] + 0x11) {
            pcVar7 = local_40;
            if ((local_50 & 1) == 0) {
                pcVar7 = pcVar5;
            }
            cVar1 = pcVar7[0x12];
            iVar2 = __ptr[0x12];
            free(__ptr);
            if (iVar2 == cVar1 + 0x12) {
            /* try { // try from 00123c94 to 00123cb8 has its CatchHandler @ 00123d08 */
                (*(*param_1)->ReleaseStringUTFChars)
                        (param_1,param_3,chars);
                p_Var6 = (*(*param_1)->NewStringUTF)(param_1,"TRUE");
            }
            ...
            if (*(long *)(in_FS_OFFSET + 0x28) == local_38) {
                return p_Var6;
            }
```

What is basically done in this series of nested if-conditions is comparing each character of the user given password/flag against the corresponding value of the valid stored one: "TRUE" is returned in case of success, "FALSE" otherwise.

The character check is in the form:

```c
        _ptr[i] == pcVar7[i] + i // for each i = 0...18
```

The variable ```pcVar7``` is highly probably storing the flag; to prove this assumption we can easily perform the following and see how the output looks like:

```c
        pcVar7[i] = _ptr[i] - i // for each i = 0...18
```

By doing this we obtain the following hex string: 
    
    \x50\x54\x52\x7b\x46\x6c\x79\x4d\x65\x54\x6f\x54\x68\x65\x4d\x6f\x6f\x6e\x7d\x0a

which is the hex representation of the flag **```PTR{FlyMeToTheMoon}```**
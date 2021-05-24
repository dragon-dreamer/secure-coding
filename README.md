# Code review cheat-sheet from security point of view

Code security review is quite a hot topic nowadays. Many developers don't really think much of security when writing code. There are many great tools which can scan code in different programming languages for typical bugs, such as [PVS Studio](https://pvs-studio.com/) or [checkmarx](https://www.checkmarx.com).  However, many companies skip static code analysis at all, and some developers just ignore compiler or analysis tool warnings. Some bugs can be easily found manually, while being ignored by automated tools.

This short cheat-sheet describes typical vulnerabilities and unsafe code patterns, which were found in code of real projects. Many of the bugs were not reported by static analysis tools. The aim of this page is to show some patterns, which you have to pay attention to when manually analyzing the code. The code patterns you'll see here should trigger you when you encounter them in real code.

The cheat-sheet will somewhat focus on `C/C++`, but will also touch some other languages.

## Unintended default enum values (Any language)
Enumeration is a well-known and wide-spread construct of many programming languages. Enumeration defines a set of distinct names in the common named scope and assigns some values to them. Unfortunately, enum mishandling may lead to critical vulnerabilities in some cases. Let's look at the following example:
```cpp
enum class UserPrivileges {
    SuperUser,
    Admin,
    User,
    Guest
};
```
Nothing bad happens here yet, but you may have noticed, that the `UserPrivileges::SuperUser` has the default value `0`. Now let's take a look at this simplified code fragment:
```cpp
struct User {
    string name;
    timestamp_t loginTime;
    bool isLoggedIn;
    UserPrivileges privileges;
    //...
};

User createDefaultUser(/* ... */) {
    //...
    return User {};
}

void loginUser(User& user, /* ... */) {
    //authenticate user,
    //fill user privileges,
    //set user.privileges,
    //set user.isLoggedIn = true
}
```
Now things get interesting. As you can see, the `createDefaultUser` function creates a default user with `privileges` field initialized to value `0` by default. This corresponds to the `UserPrivileges::SuperUser` enum value. This means, that when a new user appears in the system, this user gets the `SuperUser` privileges by default! Sometimes instead of the default constructor call or value initialization you will see a line like `memset(&user, 0, sizeof(user))`. 

Now you need to look through the code. There may be places, which first check the `isLoggedIn` boolean flag, for example:
```cpp
void readSecureData(const User& user) {
    if (!user.isLoggedIn) {
        throw NotAuthenticatedException();
    }
    
    //...
}
```
Such code fragments are secure, because `isLoggedIn` flag is `false` for a default user. However, there may be code fragments, which rely exclusively on the `privileges` field check:
```cpp
void changeDeviceSettings(const User& user) {
    if (user.privileges != UserPrivileges::SuperUser) {
        throw NotEnoughPrivilegesException();
    }
    
    //...
}
```
And here things can turn really bad. If there is a way to call this function for the unauthenticated user while bypassing other checks, privilege escalation becomes possible, and I've seen such bugs in real code. Basically, a guest user can execute some endpoints or functions, which must be accessible only to the authenticated super user!

**Advice for code reviewers and for developers:** pay attention to default enum values. Pay attention to default values of other critical fields of classes and structs. Static code analysis tools may not report such problems.

## Unhandled, unexpected, mishandled exceptions (Any language)
Exceptions is a big part of many programming languages. Unfortunately, many programmers fail to handle them correctly, which may lead to vulnerabilities in code. Let's look at some of such cases.

#### Ignoring exceptions
Some developers (especially C++) sometimes pretend, that exceptions do not exist at all. They don't use `try`, `catch` or `throw` keywords, they handle errors using return codes. Some of them even pass the `-fno-exceptions` flag to their C++ compiler. There are several major negative consequences of ignoring exceptions in languages, which support and use exceptions.

1. The first case is completely ignoring exceptions (by passing the `-fno-exceptions` flag). This basically disables all the exception-related keywords of the compiler. But the exceptions may still be there! They are extensively used in the standard C++ library. If a developer uses this library, it may throw an exception regardless of the `-fno-exceptions` flag. The library must be compiled with the `-fno-exceptions` flag, too! But this still does not solve the problem completely. All `throws` in the standard library are now replaced with calls to the `abort` function, which kills the program instantly instead of throwind an exception. There may be a bunch of denial-of-service vulnerabilities in such code! An attacker just needs to find a way to trigger any exception in the standard library, which is used by the code.

2. The second common case is forgetting to handle exceptions. Let's look at this example code:
   ```cpp
   int parseHexInteger(const std::string& str) noexcept {
       if (str.empty()) {
           return 0;
       }
       return std::stoi(str, nullptr, 16);
   }
   ```
   Here, the author of this code forgot to check, which exceptions may be thrown by the `std::stoi` function. There are several string-to-number conversion functions in C++, some of which do not throw exceptions, and some of them do. [This particular one](https://en.cppreference.com/w/cpp/string/basic_string/stol) throws `std::out_of_range` and `std::invalid_argument` exceptions, which the developer didn't expect. If this function is used to parse the untrusted input, it is extremely easy to kill the program, thus causing denial-of-service.

3. Exception mishandling is the third case we'll look at. Consider the following pseudo-code based on some real code:
   ```java
   boolean checkSignatures(List<Blob> signedBlobs) {
       bool checkPassed = false;
       
       for (Blob blob : signedBlobs) {
           try {
               checkPassed = checkSignatureForBlob(blob);
           } catch (Exception) {
               Logger.log("Incorrect signature for blob");
           }
           
           if (!checkPassed) {
               break;
           }
       }
       
       return checkPassed;
   }
   ```
   The developer checks digital signatures for an array of blobs. If any signature is incorrect, the function returns `false`. Does it? Take a minute and try to find the bug yourself.
   
   This function checks the list of blobs one by one. The first blob may be signed correctly, so the `checkPassed` variable is now set to `true`. However, all other blob signatures may be intentionally corrupted, thus causing the `checkSignatureForBlob` function throw exceptions for all of them. Notice, that the `checkPassed` variable value remains `true` in this case! When all blobs are enumerated, the `checkSignatures` function returns `true`, even that only the first blob was signed correctly! This may lead to anything like privilege escalation, denial of service, etc, because the program will process untrusted unsigned data.
   
**Advice for code reviewers:** pay close attention to exception handling in code. Are exceptions ignored? Are some exceptions missed? Are they handled correctly?

**Advice for developers:** pay close attention to exception handling. Check all the external functions you use. Do they throw exceptions? Do you handle them correctly? Do not ignore exceptions in exception-enabled languages, as the performance boost you (probably) get may not be so drastic compared to the bugs you may unintentionally bring to your code.

## Safe unsafe functions (C/C++)
Many companies currently enforce usage of so-called "safe" `C/C++` functions instead of `unsafe` ones. For example, developers must use `strcpy_s` instead of `strcpy` or `scanf_s` instead of `scanf`. Some companies enforce these rules via code checking during automated build, some of them even develop their own "safe" libraries, which provide a set of such functions.

Of course, all of the functions in the language are safe. It is only their usage that may be unsafe. If a programmer doesn't know how the function works, it is easy to make a mistake and write code with a buffer overflow (or some another) vulnerability.

Unfortunately, enforcing rules for inexperienced programmers is not the best tactics. Programmers will use whitelisted "safe" functions, yes. But they still may use them incorrectly, for example:
```cpp
void processBuffer(const char* untrustedBuffer, size_t bufferSize) {
    char tempBuf[64];
    //...
    //...
    strcpy_s(tempBuf, bufferSize, untrustedBuffer);
    //...
    //...
}
```
The second argument of the [strcpy_s](https://en.cppreference.com/w/c/string/byte/strcpy) function is `destsize` - the size of the destination buffer you are copying the string to. However, in the above code the developer passed the **source** buffer size of an untrusted buffer.

The function is "safe", but it still will overflow the `tempBuf` buffer. And I've seen similar misusage in the real code.

**Advice for code reviewers:** even if the function is "safe", check its arguments. They may be passed incorrectly, or they may be swapped.

**Advice for developers:** if you code in C++, just learn modern C++ and don't use low-level functions at all. There is an extensive standard library, which completely removes the need to use these low-level functions. If you still need to write low-level code, **carefully** check, which arguments and in which order you pass to low-level functions.

## Race conditions and their possible consequences (Any language)
Race conditions and data races are quite common in code. Multithreaded code is hard to develop. Many programmers incorrectly utilize synchronization facilities in the language of their choice, or forget to synchronize access to some shared writable variable at all. Such bugs are sometimes hard to exploit, but sometimes they are extremely handy and easy to use for an attacker. Possible consequences of race conditions are program crashes, deadlocks and livelocks, or simply unintended program behavior. [TOCTOU](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use) vulnerabilities are also race conditions, but for now I will talk about inter-thread race conditions. Let's look at the following code snippet (based on real code):
```java
import org.restlet.resource.*;

public class LoginHandler extends ServerResource {
    private static int failedLoginCount = 0;
    
    //...
    
    @Post
    public LoginResponse login(LoginRequest request) {
        if (LoginHandler.failedLoginCount == 3) {
            logger.log("user is blocked");
            return new LoginResponse("blocked");
        }
        
        if (!loginService.authenticate(request)) {
            LoginHandler.failedLoginCount = LoginHandler.failedLoginCount + 1;
            ScheduleUnblockInFiveMinutes();
            return new LoginResponse("failed");
        }
        
        LoginHandler.failedLoginCount = 0;
        return new LoginResponse("success");
    }
}
```
The code seems completely fine, until you realize that it may be called by many threads of Apache Tomcat server simultaneously. When this happens, two threads may simultaneously pass the `LoginHandler.failedLoginCount == 3` check, and then both may increment the `LoginHandler.failedLoginCount` value. If the `LoginHandler.failedLoginCount` was `2`, then it will become `4` in this case, and the check `LoginHandler.failedLoginCount == 3` will always be passed by all future login attempts, enabling the attacker to perform unlimited brute-force of the user credentials!

**Advice for code reviewers:** carefully check multi-threaded code. It may be hard, but it may be worth your time. Such vulnerabilities may not be reported by static code analysis tools.

**Advice for developers:** carefully check the multi-threaded code you write. Ask your colleagues to review such code. Do not ever [code by permutation](https://en.wikipedia.org/wiki/Programming_by_permutation) when working with several threads!

## Manual buffer manipulation and input parsing (Any language)
Well, this is a wide topic, and very many vulnerabilities and bugs have been found in code which parses something (file formats, user input, etc). With modern languages it is much more difficult to do something wrong (compared to C, for example) when parsing untrusted input, but even with high-level language facilities it is possible to make mistakes.

Let's take a look at some examples.

```cpp
//Parses the number out of the "value=123" or "value=h23f" string.
//"h" character means hexadecimal number.
//Returns 0 for invalid input.
int parseNumber(const std::string& input) {
    auto pos = input.find("value=");
    if (pos != 0) {
        return 0;
    }
    
    auto number = input.substr(std::string("value=").size());
    
    int base = 10;
    if (number.at(0) == 'h') { //hex string
        number = number.substr(1);
        base = 16;
    }
    
    try {
        return std::stoi(number, nullptr, base);
    } catch (const std::exception&) {
        return 0;
    }
}
```
This code looks fine. It handles exceptions from the `std::stoi` function, it checks if the string starts with `value=` substring... Can you spot a bug?

What will happen if we pass the `"value="` string to this function? The `number.at(0)` will throw the `std::out_of_range` exception! If the calling code doesn't handle it, the program will crash.

To the next one:
```cpp
class VideoStream {
    std::stringstream dataStream_;
    
public:
    void OnDataReceived(const std::string& data, bool keyFrame) {
        if (keyFrame) {
            ProcessFrame();
            dataStream_.str("");
        }
        dataStream_ << data;
    }
    
    void ProcessFrame() {
        //...
    }
    
    //...
};
```
Here the developer is parsing the video stream from the possibly untrusted client. Data from the client is appended to the `dataStream_` buffer until the `keyFrame` flag is received. But what if the client never sends the `keyFrame` flag? The `dataStream_` buffer will infinitely grow and may take up all the available memory, disrupting other services on the server and possibly crashing!

The next example:
```cpp
using CharCount = std::array<int, 256>;
CharCount countChars(const std::string& input) {
    CharCount count {};
    for (char ch : input) {
        ++count[ch];
    }
    return count;
}
```
This function counts, how many times each character is used in the input string, and returns the `CharCount` array with the calculated counts for each character. What can go wrong here?!

Well, everything can. At first, the developer has incorrectly assumed that the maximum value for the `char` type variabe is `256`. The developer should have used the `numeric_limits<char>::max()` to determine this.

But what is much worse, the `char` type can be either `signed` or `unsigned`, depending on the compiler settings. If this type is `signed` for your compiler, then the attacker may overwrite memory outside of the `count` array, passing the string like this: `"test_str\xde"`. The `"\xde"` character may have the `-34` value (if represented as a `signed char`). Basically, the attacker now can address negative array offsets, writing outside of the `count` array memory!

Let's conclude with a really simple one (even detectable by automatic analysis tools, even **reported by a compiler**), but which I still encountered several times:
```cpp
std::string str = getUntrustedString();
auto pos = str.find("text");
if (pos < 0) {
    return;
}
```

The `pos` variable is `unsigned` (of the `size_t` type). Thus, it can never be less then zero, and the check will always pass. The correct check is:
```cpp
std::string str = getUntrustedString();
auto pos = str.find("text");
if (pos == std::string::npos) {
    return;
}
```

**Advice for code reviewers:** check parsing code carefully, especially when it may parse untrusted user input. Read it manually, check it using automated tools, write fuzzing tests for it.

**Advice for developers:** Do not ever [code by permutation](https://en.wikipedia.org/wiki/Programming_by_permutation) when parsing something! Do not trust user input in any way, check it as carefully as possible.

## Missed switch cases (All languages)
This is the one automated tools may tell you about in some cases. Let's start with an example:
```cpp
const int ChangePermissions = 1;
const int ReadData = 2;
const int WriteData = 3;

//...

bool HandleMessage(const Message& msg) {
    bool handled = true;
    
    switch (msg.getType()) {
    case ChangePermissions:
        handled = ChangePermissions(msg);
        break;
    case ReadData:
        handled = ReadData(msg);
        break;
    case WriteData:
        handled = WriteData(msg);
        break;
    }
    
    if (!handled) {
        return false;
    }
    
    SendAnswerForMessage(msg);
    return true;
}
```
As you can see, there is no `default` case in the `switch-case` clause. This means, the developer may forget to add a message handling `case` for a new message, which may be added many months after the initial code was written. This is especially true, when there are several separate functions handling different sets of messages. For this new message, `handled` will be `true`, and the code will call `SendAnswerForMessage` for an unchecked and unhandled message, causing unintended behavior.

I believe, that for the code above, even automated static analysis tools will be silent. If there was `enum` instead of just numeric constants, tools would warn of unhandled `enum` values inside the `switch`. With just constants (or macros), there is no way for a tool to determine, which values must be handled in the `switch-case`!

**Advice for code reviewers:** check if all necessary cases are handled in `switch-case` clauses, or if the `default` case is present. Check the `default` case for correctness.

**Advice for developers:** Carefully write `switch-case` clauses. Do not miss cases. Add the `default` case, which does something reasonable for unexpected cases. Put `case` values to enumeration (don't use constants or macros), so that automated analysis tools could warn you, if you forgot to handle a value inside your `switch`.

## Possibly vulnerable libraries or their incorrect usage (All languages)
There are some libraries, which have to trigger you as a code reviewer, when you see them in code.
1. Any ZIP archive unpacking library. Or code, which unpacks ZIP archives manually. There is that infamous [Zip Slip](https://github.com/snyk/zip-slip-vulnerability) vulnerability, which is still present in different libraries by design. If used incorrectly, it opens a hole in software, which may allow an attacker to overwrite any file on the system!
2. Any library for the XML format processing. There is [XXE](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing) vulnerabilities, and if you encounter XML processing in code, there is a chance, that these vulnerabilities may be present.

## TOCTOU with file operations (All languages)
Any file operations present in code may be vulnerable to [TOCTOU](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use) attacks. For example:
- The file signature is first checked, and then the file is reopened and processed.
- The file is first written, and then restrictive file permissions are set.

**Advice for code reviewers:** when you encounter file operations in code, pay close attention to presence of race conditions, which may lead to TOCTOU attacks. Race conditions with file operations are extremely common.

**Advice for developers:** Think about the order of file operations. Can it lead to race conditions in some cases?

## Improper logging
Often software writes logs. However, often logging is implemented incorrectly from the security point of view. Let's look at some improper logging scenarios:
1. **Improper log entries escaping.** Logs often contain data received from the untrusted user. This data may contain any characters (including a newline character, null-bytes, etc). If this data is not properly escaped, an attacker may break log formatting. For example, new fake lines may be added to program logs, making log analysis more difficult or even impossible.
2. **Writing unmasked secrets to logs.** Often developers write user secrets to logs (and often unintentionally). One case of such unintentional secrets logging is exception logging. for example:
   ```java
   void Authenticate(string login, string password) {
       try {
           AuthenticateUser(login, password);
       } catch (AuthException e) {
           Logger.logException("Unable to authenticate", e);
       }
   }
   ```
   Here, `e` may contain the user login and password, which will end up in logs in case an exception is thrown. An exception stacktrace may also contain function argument values (`string login`, `string password`).

   Passwords not only end up in a log file with possibly unrestricted read permissions. These log files also may be taken by the server administrator and transferred via insecure channels for additional analysis or backup!

**Advice for code reviewers:** pay attention to how logging is implemented. Are untrusted strings properly escaped? Is there any secrets that may end up in log files?

**Advice for developers:** Escape untrusted user data which is being written to logs. Do not write any user secrets to logs or mask them properly. Check how you log exceptions, as they may contain user secrets as well.

## Passing secrets to another program via the command line (All languages)
To pass secrets to another programs via the command line is quite a bad idea. On Linux, command lines with arguments may be visible in the process list (`ps`, `/proc`). They may be also logged to audit logs or `/var/log/...` logs. On Windows, the situation is similar: command lines with arguments may be readable from the process list, and they also [may be logged to the Event log](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing).

**Advice for code reviewers:** If you see an invocation of an external program in code, check if there are any secrets, which are passed to that program via the command line.

**Advice for developers:** Do not pass secrets to external programs via the command line. Use interactive input (pipes) or other means to do this.

## Excessive privileges for a resource
When any resource is acquired in code, it is in the best interest to request as less privileges as possible. Here are some examples:
- A file is opened. If the program is going to only read the file, then it doesn't need write access to that file.
- A database user is created. If the purpose of this user is to write data to tables, then it should not have `alter table` permissions.
- A process is opened to query information about it. Thus, its handle doesn't need the `PROCESS_ALL_ACCESS` access attribute.

Excessive resource privileges may allow an attacker to perform an attack, which otherwise would not be possible.

**Advice for code reviewers:** Look through the acquired resource privileges, and what privileges they really require.

**Advice for developers:** Do not grant excessive permissions to the resource handles you acquire.

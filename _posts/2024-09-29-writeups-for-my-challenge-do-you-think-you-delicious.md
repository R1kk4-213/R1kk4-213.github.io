---
title: "Writeups For My Challenge: Do You Think You Delicious"
date: 2024-09-29 14:56 +0700
categories: [Cybersecurity, CTF]
tags: [writeup, "Do You Think You Delicious", sql-injection, ssti]
media_subpath: /assets/do-you-think-you-delicious
---


# Introduction
---

In this challenge, the goal is to exploit a series of vulnerabilities step by step, beginning with SQL injection (SQLi), which can be leveraged to write a file. This, in turn, will lead to a server-side template injection (SSTI), ultimately revealing the flag.

### Unintended : 
There is also an unintended solution where SQLi can be used to directly read files, including `/proc/self/environ`, allowing sensitive data to be accessed more quickly.

# Overview

The web application initially presents itself with a simple interface that includes a registration and login form.

 
![alt text](image_1.png)

After successfully registering and logging in, we are redirected to the poem site.

![alt text](image_2.png)

So where is the vuln?

# Dive in code

In **Entrypoint.sh** we have the following snippet code:
```
FLAG=${FLAG:-bkisc{default_flag}}
ESCAPED_FLAG=$(echo "$FLAG" | sed "s/'/''/g")

mysql -u root -e "
CREATE DATABASE IF NOT EXISTS $DB_NAME;
USE $DB_NAME;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';
GRANT SELECT, INSERT ON $DB_NAME.* TO '$DB_USER'@'localhost';
GRANT FILE ON *.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
CREATE TABLE IF NOT EXISTS users (
  id INT NOT NULL AUTO_INCREMENT,
  username VARCHAR(85) UNIQUE,
  password VARCHAR(120) NOT NULL,
  is_admin TINYINT(1) DEFAULT 0,
  PRIMARY KEY (id)
);
INSERT INTO users (username, password, is_admin)
VALUES ('admin', MD5('${ESCAPED_FLAG}'), 1)
ON DUPLICATE KEY UPDATE password=VALUES(password);
```
It seems like the application creates a database called `bkisc` with a `users` table and adds a record for the `admin` user with the password set to `flag`. However, upon closer inspection, we can see that the flag has been hashed using MD5. This appears to be a troll by the author.

Looking more clearly, we can see that flag also placed in `app.py`. Looking more legit.

```
app.config['FLAG'] = os.getenv('FLAG', 'BKISC{real_flag}')
app.config['TEMPLATES_AUTO_RELOAD'] = True
```
The flag should ideally be stored in the environment variables. There are several ways to locate the flag in the environment, such as:

* Reading the `/proc/self/environ` file
* Remote Code Execution (RCE)
* Server-Side Template Injection (SSTI)

The intended solution for this challenge is SSTI, as we can observe the following line in the `Dockerfile`:

```
RUN chown -R flask
/app/templates
```

and in `app.py`:
```
@app.route('/poem/<path:poem_id>')
def poem(poem_id):
    if not re.match(r'^[a-zA-Z0-9_]+$', poem_id):
        abort(400, description="Invalid poem ID")
    template_name = f'poems/poem_{poem_id}.html'
    try:
        return render_template(template_name)
    except Exception as e:
        print(f"Error rendering poem: {e}")
        return abort(404, description="Poem not found");
```

So the idea is to find the way to create a file with content `{{config}}` in `/app/templates/poems/*` . and access it via the route `/poem/<path:poem_id>`. Then it will render all env parameter as following.

![alt text](image_3.png)


```
abc' UNION SELECT '{{ config }}',1 INTO OUTFILE '/app/templates/poems/poem_3.html' #
```

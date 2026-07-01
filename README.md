# poc-types-of-authentication

POC demonstrando quatro estratégias de autenticação em uma aplicação Spring Boot, cada uma isolada em seu próprio `SecurityFilterChain`.

## Stack

| Tecnologia | Versão |
|---|---|
| Java | 21 |
| Spring Boot | 4.0.6 |
| Spring Security | (managed) |
| jjwt | 0.12.7 |
| Lombok | (managed) |

---

## Arquitetura

```
src/main/java/.../
├── config/
│   └── SecurityConfig.java        # 4 FilterChains isoladas por path
├── controller/
│   ├── BasicAuthController.java   # GET /http-basic/**
│   ├── JWTController.java         # POST|GET /jwt/**
│   ├── ApiKeyController.java      # GET /apikey/**
│   └── SocialLoginController.java # GET /social/**
├── filter/
│   ├── JwtAuthFilter.java         # Valida Bearer JWT
│   ├── ApiKeyAuthFilter.java      # Valida header X-API-Key
│   └── ApiKeyRateLimitFilter.java # Rate limit: 10 req/min por chave
├── service/
│   ├── JwtService.java            # Gera e valida access tokens JWT
│   ├── RefreshTokenService.java   # Gerencia refresh tokens opacos (UUID)
│   └── UserDetailsServiceImpl.java
├── repository/
│   ├── UserRepository.java        # Usuários em memória (POC)
│   └── ApiKeyRepository.java      # API Keys em memória (POC)
└── model/
    └── UserModel.java
```

### Isolamento das FilterChains

| Order | Path | Mecanismo |
|-------|------|-----------|
| 1 | `/http-basic/**` | HTTP Basic Auth |
| 2 | `/jwt/**` | JWT (Bearer token) |
| 3 | `/apikey/**` | API Key (`X-API-Key` header) |
| 4 | `/social/**`, `/oauth2/**`, `/login/oauth2/**` | OAuth2 / GitHub |

---

## Usuários e credenciais (memória)

### Basic Auth / JWT

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | ADMIN |
| `user` | `user123` | USER |

### API Keys

| Chave | Usuário | Role |
|-------|---------|------|
| `key-admin-123` | admin-service | ADMIN |
| `key-user-456` | user-service | USER |

---

## Como rodar

```bash
# Clonar e subir
./gradlew bootRun

# Ou com profile local (OAuth2 configurado)
./gradlew bootRun --args='--spring.profiles.active=local'
```

A aplicação sobe em `http://localhost:8080`.

Para Social Login, configure as variáveis de ambiente antes de subir:

```bash
export GITHUB_CLIENT_ID=seu_client_id
export GITHUB_CLIENT_SECRET=seu_client_secret
```

E no `application.yml`:
```yaml
spring.security.oauth2.client.registration.github:
  client-id: ${GITHUB_CLIENT_ID}
  client-secret: ${GITHUB_CLIENT_SECRET}
```

---

## Testes Funcionais

### 1. HTTP Basic Auth

Apenas usuários com role `ADMIN` têm acesso. Credenciais enviadas via header `Authorization: Basic <base64(user:pass)>`.

#### ✅ Acesso autorizado (admin)

```bash
curl -u admin:admin123 http://localhost:8080/http-basic/dashboard
```

Resposta esperada (`200 OK`):
```json
{
  "message": "Área administrativa - apenas ADMIN",
  "loggedAs": "admin",
  "users": ["admin", "user"]
}
```

#### ✅ Settings (admin)

```bash
curl -u admin:admin123 http://localhost:8080/http-basic/settings
```

Resposta esperada (`200 OK`):
```json
{
  "feature.basicAuth": "enabled",
  "session.policy": "STATELESS",
  "password.encoder": "BCrypt"
}
```

#### ❌ Acesso negado (user sem role ADMIN)

```bash
curl -u user:user123 http://localhost:8080/http-basic/dashboard
```

Resposta esperada: `403 Forbidden`

#### ❌ Credenciais inválidas

```bash
curl -u admin:senha-errada http://localhost:8080/http-basic/dashboard
```

Resposta esperada: `401 Unauthorized`

---

### 2. JWT (Access Token + Refresh Token)

Fluxo: `login` → recebe `access_token` (JWT, 15 min) + `refresh_token` (UUID opaco, 7 dias) → usa `access_token` nas requisições → renova com `refresh_token` → `logout` revoga o refresh token.

#### ✅ Login

```bash
curl -s -X POST http://localhost:8080/jwt/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

Resposta esperada (`200 OK`):
```json
{
  "access_token":  "eyJhbGci...",
  "refresh_token": "550e8400-e29b-41d4-a716-446655440000",
  "token_type":    "Bearer",
  "expires_in":    "900"
}
```

#### ✅ Acessar endpoint protegido com access token

```bash
ACCESS_TOKEN="eyJhbGci..."

curl http://localhost:8080/jwt/dashboard \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

Resposta esperada (`200 OK`):
```json
{
  "message":  "Área protegida por JWT",
  "loggedAs": "admin"
}
```

#### ✅ Endpoint exclusivo ADMIN

```bash
curl http://localhost:8080/jwt/admin \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

Resposta esperada (`200 OK`) com admin / `403 Forbidden` com user.

#### ✅ Renovar tokens (refresh)

```bash
REFRESH_TOKEN="550e8400-e29b-41d4-a716-446655440000"

curl -s -X POST http://localhost:8080/jwt/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}"
```

Resposta esperada (`200 OK`) — novo par de tokens:
```json
{
  "access_token":  "eyJhbGci...(novo)",
  "refresh_token": "7c9e6679-...(novo UUID)",
  "token_type":    "Bearer",
  "expires_in":    "900"
}
```

> O refresh token anterior é revogado automaticamente (rotation).

#### ✅ Logout

```bash
curl -s -X POST http://localhost:8080/jwt/logout \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}"
```

Resposta esperada (`200 OK`):
```json
{ "message": "Logout realizado com sucesso" }
```

#### ❌ Refresh token inválido / já usado

```bash
curl -s -X POST http://localhost:8080/jwt/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "token-invalido"}'
```

Resposta esperada (`401 Unauthorized`):
```json
{ "error": "Refresh token inválido ou expirado" }
```

#### ❌ Access token expirado ou malformado

```bash
curl http://localhost:8080/jwt/dashboard \
  -H "Authorization: Bearer token.invalido.aqui"
```

Resposta esperada: `403 Forbidden`

#### ❌ Credenciais inválidas no login

```bash
curl -s -X POST http://localhost:8080/jwt/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "errada"}'
```

Resposta esperada: `401 Unauthorized`

---

### 3. API Key

Autenticação via header `X-API-Key`. Rate limit de **10 requisições por minuto** por chave.

#### ✅ Acesso com chave de usuário

```bash
curl http://localhost:8080/apikey/data \
  -H "X-API-Key: key-user-456"
```

Resposta esperada (`200 OK`):
```json
{
  "message":     "Acesso via API Key",
  "loggedAs":    "user-service",
  "authorities": "[ROLE_USER]"
}
```

#### ✅ Acesso admin com chave de admin

```bash
curl http://localhost:8080/apikey/admin \
  -H "X-API-Key: key-admin-123"
```

Resposta esperada (`200 OK`):
```json
{
  "message":     "Área admin via API Key",
  "loggedAs":    "admin-service",
  "authorities": "[ROLE_ADMIN]"
}
```

#### ❌ Chave sem role ADMIN tentando acessar /admin

```bash
curl http://localhost:8080/apikey/admin \
  -H "X-API-Key: key-user-456"
```

Resposta esperada: `403 Forbidden`

#### ❌ Chave inválida

```bash
curl http://localhost:8080/apikey/data \
  -H "X-API-Key: chave-inexistente"
```

Resposta esperada: `403 Forbidden`

#### ❌ Sem header X-API-Key

```bash
curl http://localhost:8080/apikey/data
```

Resposta esperada: `403 Forbidden`

#### ⚠️ Rate limit excedido (após 10 requisições no mesmo minuto)

```bash
# Execute 11 vezes seguidas
for i in $(seq 1 11); do
  curl -s -o /dev/null -w "req $i: %{http_code}\n" \
    http://localhost:8080/apikey/data \
    -H "X-API-Key: key-user-456"
done
```

Resposta da 11ª requisição (`429 Too Many Requests`):
```json
{
  "error": "Too Many Requests",
  "message": "Limite de 10 requisições/minuto excedido. Tente novamente em instantes."
}
```

Headers de controle retornados em todas as respostas:
```
X-RateLimit-Limit:     10
X-RateLimit-Remaining: 9  (diminui a cada requisição)
```

---

### 4. Social Login (OAuth2 / GitHub)

Fluxo browser-based via OAuth2 Authorization Code. Não testável via `curl` puro (requer redirecionamento de browser).

#### Pré-requisitos

1. Criar OAuth App no GitHub: **Settings → Developer settings → OAuth Apps → New OAuth App**
   - Homepage URL: `http://localhost:8080`
   - Callback URL: `http://localhost:8080/login/oauth2/code/github`
2. Configurar as credenciais (variáveis de ambiente ou `application-local.yml`)
3. Subir com `--spring.profiles.active=local`

#### Fluxo de teste manual (browser)

1. Acesse `http://localhost:8080/social/profile` — será redirecionado para o GitHub
2. Autorize o acesso no GitHub
3. Após o callback, receberá:

```json
{
  "message":   "Autenticado via GitHub",
  "login":     "seu-username-github",
  "name":      "Seu Nome",
  "email":     "seu@email.com",
  "avatarUrl": "https://avatars.githubusercontent.com/..."
}
```

> **Nota:** O campo `email` pode aparecer como `"null"` caso o e-mail do perfil GitHub esteja definido como privado.

---

## Diferenças entre as abordagens

| Característica | Basic Auth | JWT | API Key | Social Login |
|---|---|---|---|---|
| Credencial enviada a cada req | ✅ Sim | ❌ Não (stateless) | ✅ Sim | ❌ Não (sessão OAuth2) |
| Expiração automática | ❌ Não | ✅ Sim (15 min) | ❌ Não | ✅ Sim (token OAuth2) |
| Revogação | ❌ Não | ✅ Sim (logout/rotation) | ❌ Sem infraestrutura | ✅ Via GitHub |
| Ideal para | Ferramentas internas / M2M simples | SPAs / Mobile | Integrações M2M | Login de usuários finais |
| Rate limiting nativo | ❌ | ❌ | ✅ 10 req/min | ❌ |

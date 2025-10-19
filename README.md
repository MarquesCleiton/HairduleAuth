
# HairduleAuth — Lambda de Autenticação (Login, Refresh, Logout)

Esta Lambda faz parte do ecossistema **Hairdule**, responsável por autenticar usuários, validar senhas e futuramente emitir tokens JWT.

---

## 🧭 Visão Geral

**Serviço:** `hairdule-auth`  
**Infraestrutura:** AWS Lambda + DynamoDB (tabela `HairduleTB`)  
**Deploy:** AWS SAM CLI  
**Região:** `us-east-1`  

---

## 📁 Estrutura do Projeto

```
hairdule-auth/
├─ src/
│  ├─ app.py                 # Entry point da Lambda
│  ├─ core/
│  │  ├─ ddb_client.py       # Cliente do DynamoDB
│  │  ├─ response.py         # Classe HttpResponse padrão
│  ├─ routes/
│  │  ├─ base_strategy.py    # Classe base para estratégias
│  │  ├─ login_strategy.py   # Lógica da rota /auth/login
│  │  ├─ router.py           # Resolve a rota e executa a estratégia
│  ├─ utils/
│  │  ├─ crypto_utils.py     # Funções de hashing e verificação bcrypt
│  │  ├─ logger.py           # Logger estruturado (com stacktrace)
│  ├─ __init__.py
├─ events/
│  └─ login.json             # Exemplo de evento local
├─ template.yaml             # Infraestrutura SAM
├─ requirements.txt          # Dependências Python
├─ samconfig.toml            # Configuração de deploy
└─ .gitignore
```

---

## 🔑 Pré-requisitos

- **AWS CLI** configurado (`aws configure`)
- **Docker Desktop** instalado e em execução
- **AWS SAM CLI** instalado
- **Conta AWS** com permissões de CloudFormation, Lambda, S3 e DynamoDB

---

## 🧰 Configuração Inicial

### 1️⃣ Login na AWS

```bash
aws configure
```
Informe:
- `AWS Access Key ID`
- `AWS Secret Access Key`
- `Default region name`: `us-east-1`
- `Default output format`: `json`

Verifique se está autenticado:
```bash
aws sts get-caller-identity
```

---

### 2️⃣ DynamoDB (HairduleDB)

Esta Lambda usa a tabela **HairduleTB**, criada pela stack `hairdule-db`.  
Para testar localmente, você pode rodar o DynamoDB em Docker:

```bash
docker network create hairdule-net
docker run -d --name ddb-local --network hairdule-net -p 8000:8000 amazon/dynamodb-local
```

Depois crie a tabela:
```bash
aws dynamodb create-table --cli-input-json file://create-table.json --endpoint-url http://localhost:8000
```

E insira um usuário de teste:
```bash
aws dynamodb put-item   --table-name HairduleTB   --item '{
    "pk": {"S": "USER#1"},
    "sk": {"S": "PROFILE"},
    "email": {"S": "teste@exemplo.com"},
    "passwordHash": {"S": "$2b$12$T7XQeGg1MZy4Amv7czfPuOj2y9E8Wd2BYD7AQbKTV8G9E8xNU4EGu"},
    "name": {"S": "Cleiton"}
  }'   --endpoint-url http://localhost:8000
```

---

### 3️⃣ Variáveis de ambiente (AWS Lambda)

| Nome | Valor | Descrição |
|------|--------|------------|
| `TABLE_NAME` | HairduleTB | Nome da tabela DynamoDB |
| `AUTH_JWT_SECRET_SSM` | /hairdule/jwt/secret | Caminho no Parameter Store |
| `TOKEN_EXP_MINUTES` | 5 | Tempo de expiração do JWT |
| `REFRESH_EXP_DAYS` | 7 | Tempo de expiração do refresh token |
| `SERVICE_NAME` | hairdule-auth | Nome do serviço |
| `DYNAMODB_ENDPOINT` | *(deixe vazio em produção)* | Endpoint local se for teste |

---

## 🚀 Deploy para AWS

### Primeiro deploy
```bash
sam build
sam deploy --guided
```
- **Stack name:** HairduleAuth  
- **Region:** us-east-1  
- **Confirm changeset:** Y  
- **Allow IAM role creation:** Y  
- **Save arguments to samconfig.toml:** Y  

### Próximos deploys
```bash
sam build
sam deploy
```

---

## 🔐 Permissões IAM

A Lambda precisa ter permissão para acessar **a tabela e seus índices**:

```yaml
Policies:
  - AWSLambdaBasicExecutionRole
  - Statement:
      - Effect: Allow
        Action:
          - dynamodb:GetItem
          - dynamodb:PutItem
          - dynamodb:UpdateItem
          - dynamodb:Query
          - dynamodb:DeleteItem
        Resource:
          - !Sub arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/HairduleTB
          - !Sub arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/HairduleTB/index/*
```

---

## 🧪 Testando Localmente

### Evento de teste (`events/login.json`)
```json
{
  "rawPath": "/auth/login",
  "body": "{"email": "teste@exemplo.com", "password": "minhasenha123"}"
}
```

### Executar no SAM Local
```bash
sam build --use-container
sam local invoke AuthFunction --event events/login.json --docker-network hairdule-net
```

---

## 🌐 Teste Online (API Gateway)

Após o deploy, copie a URL exibida pelo SAM:

```
https://xxxxx.execute-api.us-east-1.amazonaws.com/auth/login
```

Teste via **Postman**:
```json
POST https://xxxxx.execute-api.us-east-1.amazonaws.com/auth/login
Content-Type: application/json

{
  "email": "teste@exemplo.com",
  "password": "minhasenha123"
}
```

✅ Resposta esperada:
```json
{
  "message": "Senha válida, pronto para gerar tokens",
  "pk": "USER#1"
}
```

---

## 🪵 Logs e Debug

### Consultar logs no CloudWatch:
```bash
sam logs --name AuthFunction --region us-east-1 --tail
```

### Estrutura dos logs
Os logs são estruturados em JSON:
```json
{
  "timestamp": "2025-10-19T15:52:59.716Z",
  "level": "INFO",
  "service": "hairdule-auth",
  "logCode": "AUTH-LOGIN-200-1",
  "logMessage": "Login validação inicial OK",
  "payload": {"email_masked": "te***@exemplo.com"}
}
```

Erros incluem stacktrace completo:
```json
{
  "level": "ERROR",
  "service": "hairdule-auth",
  "logMessage": "Erro ao consultar usuário no DynamoDB",
  "stacktrace": ["Traceback (most recent call last): ..."]
}
```

---

## 🔮 Próximos Passos

| Etapa | Descrição | Status |
|--------|------------|---------|
| ✅ Login básico | Validação de e-mail e senha | Concluído |
| 🔒 JWT Tokens | Gerar tokens e refresh | Próximo |
| 🧠 Authorizer | Nova Lambda para validar JWTs | Próximo |
| 🧭 Business Lambda | Operações principais da barbearia | Próximo |
| 🧹 Integração | Remover API Gateway e conectar ao Authorizer | Futuro |

---

## 📚 Referências

- [AWS SAM Developer Guide](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/)
- [AWS DynamoDB Docs](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Introduction.html)
- [Bcrypt Python](https://pypi.org/project/bcrypt/)
- [AWS Lambda Permissions](https://docs.aws.amazon.com/lambda/latest/dg/access-control-identity-based.html)

---

**Autor:** Cleiton Marques  
**Data:** 19/10/2025  
**Projeto:** Hairdule Ecosystem 🪞✂️  

# SpiderPrint Authentication System

Sistema de autenticação profissional para o software SpiderPrint com controle de licenças e dashboard administrativo.

## Funcionalidades

- ✅ **Autenticação por hardware** - Identificação única do dispositivo
- ✅ **Controle de licenças** - Trial, Básica, Avançada, Premium
- ✅ **Sessão única** - Impede múltiplos acessos simultâneos
- ✅ **Dashboard administrativo** - Interface web para gerenciamento
- ✅ **API REST** - Endpoints para integração com cliente
- ✅ **Banco PostgreSQL** - Dados seguros e escaláveis

## Deploy no DigitalOcean

Este projeto está configurado para deploy automático no DigitalOcean App Platform.

### Configuração

1. Conecte seu repositório GitHub ao DigitalOcean
2. O banco PostgreSQL será criado automaticamente
3. As variáveis de ambiente são configuradas via app.yaml

### URLs da API

- `POST /api/auth/login` - Login do usuário
- `POST /api/auth/logout` - Logout do usuário
- `POST /api/auth/verify` - Verificar sessão
- `GET /api/users` - Listar usuários (admin)
- `POST /api/users` - Criar usuário (admin)
- `PUT /api/users/{id}/license` - Atualizar licença
- `GET /api/stats` - Estatísticas do sistema

### Dashboard Administrativo

Acesse a URL raiz da aplicação para o dashboard web.

**Login padrão:**
- Usuário: admin
- Senha: admin123

## Desenvolvimento Local

```bash
pip install -r requirements.txt
python app.py
```

## Estrutura do Projeto

```
spiderprint_digitalocean/
├── app.py                 # Aplicação Flask principal
├── requirements.txt       # Dependências Python
├── gunicorn.conf.py      # Configuração do servidor
├── .do/app.yaml          # Configuração DigitalOcean
├── static/               # Dashboard administrativo
│   └── index.html
└── README.md             # Esta documentação
```

## Licença

Propriedade da SpiderGrid - Todos os direitos reservados.


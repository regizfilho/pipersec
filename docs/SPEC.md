# Especificação — vpnctl

## Objetivo

PiperSec é uma interface gráfica desktop para Linux que administra perfis de
VPN IPsec/IKEv1 operados pelo strongSwan (`swanctl`). O atalho abre uma janela
nativa GTK e elimina a edição manual dos arquivos de configuração. A CLI
permanece como interface técnica opcional.

## Requisitos funcionais

- Criar, listar, inspecionar, alterar e remover perfis.
- Conectar, desconectar e consultar o estado de cada perfil.
- Disponibilizar todas as operações diárias em interface gráfica, acessível no
  menu de aplicativos, sem terminal.
- Gerar configurações `swanctl.conf` e de credenciais compatíveis com IKEv1,
  PSK e XAuth, incluindo os parâmetros do exemplo fornecido.
- Persistir múltiplos perfis no diretório de configuração do usuário.
- Oferecer `import-example` para criar um perfil genérico, sem gravar
  credenciais reais.
- Disponibilizar um painel de estado e notificações para indicar conexão e
  desconexão.

## Modelo de perfil

Cada perfil possui nome, endereço remoto, versão IKE, modo agressivo, VIP,
propostas IKE/ESP, temporizadores DPD/reautenticação/rekey, sub-rede remota,
usuário XAuth, identidade PSK e segredos XAuth/PSK. O nome é limitado a
`[A-Za-z0-9_-]` para impedir injeção em nomes usados pelo strongSwan.

## Segurança

- Perfis, inclusive senhas, são serializados como JSON e cifrados com
  AES-256-GCM.
- A chave aleatória de 32 bytes fica em `master.key` com modo `0600`; o
  diretório da aplicação recebe modo `0700`.
- A criação de arquivos é atômica e usa permissões restritivas.
- Para conectar, a interface solicita autorização por `pkexec`, cria uma
  configuração temporária protegida e a remove ao final, inclusive em falha.
- Dados de perfil são validados e caracteres de controle são recusados antes
  de renderizar a configuração.

## Integração strongSwan

O host precisa ter o daemon strongSwan/swanctl ativo e o usuário precisa poder
autorizar `pkexec swanctl` no diálogo gráfico do sistema. `connect` carrega somente o perfil selecionado,
carrega suas credenciais e inicia o child SA homônimo. `disconnect` termina o
IKE SA do perfil. Como o `swanctl` não tem uma operação segura para descarregar
credenciais de apenas um perfil, as definições carregadas permanecem no daemon
até a reinicialização dele, sem interferir em perfis de terceiros. O estado é
obtido com `swanctl --list-sas --ike <nome>`.

## Critérios de aceite

1. `go test ./...` passa sem exigir root, rede ou strongSwan instalado.
2. `go build ./cmd/vpnctl` produz um binário utilizável.
3. Dois perfis podem ser criados e listados sem mistura de credenciais.
4. A configuração gerada contém os campos equivalentes ao exemplo do usuário.
5. O pacote Debian contém fonte, documentação e instruções de instalação.

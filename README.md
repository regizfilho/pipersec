# pipersec

**PiperSec** é um aplicativo desktop para Linux que simplifica a criação e a
operação de conexões VPN IPsec com strongSwan. Ele foi pensado para pessoas que
recebem os parâmetros de uma VPN corporativa e não querem editar manualmente
arquivos `swanctl.conf` ou usar comandos no terminal todos os dias.

## Objetivo

- Criar e administrar vários perfis VPN em uma interface gráfica moderna.
- Conectar e desconectar VPNs IPsec/IKEv1 com PSK e XAuth.
- Exibir o estado da conexão na aplicação, em notificações e, quando houver
  suporte do desktop, na bandeja do sistema.
- Gerar configurações compatíveis com strongSwan sem expor senhas na tela,
  nos logs ou no repositório.

## Segurança e privacidade

As informações dos perfis ficam somente no computador do usuário, em
`~/.config/vpnctl/profiles.enc`, cifradas com AES-256-GCM. A chave local fica
em `~/.config/vpnctl/master.key`, com permissões restritas ao usuário.

Durante a conexão, o PiperSec cria uma configuração temporária acessível
somente ao root, carrega-a no strongSwan e a remove logo em seguida. Nenhum
gateway, usuário, senha XAuth, identidade PSK ou chave PSK deve ser colocado
no código-fonte, em issues, capturas de tela públicas ou commits.

O arquivo `.gitignore` deste projeto bloqueia perfis, chaves, certificados,
arquivos de ambiente e artefatos de compilação. Antes de publicar alterações,
revise sempre `git status` e `git diff --cached`.

## Instalação no Ubuntu/Debian

Baixe ou gere o pacote `.deb` e instale-o:

```bash
sudo apt install ./vpnctl_1.0.0_amd64.deb
```

O pacote instala as dependências do strongSwan e cria o atalho **PiperSec —
Conexão VPN via IPsec** no menu de aplicativos.

## Como usar

1. Abra **PiperSec** pelo menu de aplicativos.
2. Crie um perfil e informe os dados fornecidos pelo administrador da VPN:
   gateway, usuário e senha XAuth, identidade e chave PSK.
3. Escolha IKEv1/XAuth quando essa for a configuração recebida; os campos
   avançados possuem dicas para propostas, DPD, IP virtual e redes remotas.
4. Salve o perfil, selecione-o e clique em **Conectar**.
5. Autorize a operação no diálogo gráfico do sistema. Não é necessário usar o
   terminal para o uso diário.

## Desenvolvimento

```bash
make test
make build
make deb
```

O projeto é escrito principalmente em Go. A interface desktop utiliza GTK e
integra-se ao `swanctl`/strongSwan por meio de autorização gráfica.

Mais detalhes de arquitetura e critérios de aceite estão em
[docs/SPEC.md](docs/SPEC.md).

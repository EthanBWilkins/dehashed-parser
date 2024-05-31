# dehashed-wrapper
Extract simple user and password lists from Dehashed API. Supports multiple output list formats. Easy to fork and add more output types.

# Usage
**Basic:** `python3 dehashed-wrapper.py -d <domain> -e <email> -k <api-key> -oA <output-prefix>`

**Options**

```
options:
  -h, --help                            show this help message and exit
  -d <domain>, --domain <domain>        The domain to search. Cannot be used with custom query
  -q <query>, --custom-query <query>    Custom Dehashed query. Cannot be used with -d / --domain
  -e <email>, --email <email>           Dehashed account email
  -k <api key>, --api-key <api key>     Dehashed API Key
  -uu, --unique-usernames               Remove duplicate records by username.
  -ue, --unique-emails                  Remove duplicate records by email.
  -oU <file>            Usernames output file. Parallel order with -oP. Usersnames with no associated password are at the end of the list.
  -oE <file>            Emails output file.
  -oP <file>            Passwords output file. Parallel with output from oU
  -oUH <file>           Output file for colon-delimited usernames and password hashes. username:hash
  -oEH <file>           Output file for colon-delimited emails and password hashes. email:hash
  -oUP <file>           Output file for colon-delimited usernames and passwords. username:password
  -oEP <file>           Output file for colon-delimited emails and passwords. email:password
  -oA <prefix>          Output in all formats except 'oPEP'. Argument is file prefix.
  -oPEP <prefix>        Parallel Email and Password lists. Argument is file prefix. Not included with -oA.
```
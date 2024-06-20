#############################
# dehashed-wrapper.py       #
# Author: Ethan Wilkins     #
# - GitHub: EthanBWilkins   #
#############################

# Imports
import argparse
import requests
from requests.auth import HTTPBasicAuth

# Global Variables
URL = "https://api.dehashed.com/search"

# Future Features
# 1. support API response paging and page size. Currently limited to first 10k results. 

# Code 
def call_api(email, key, search, custom=False):
    query = f"{search}" if custom else f"domain:{search}"
    query_params = { 
        "query": query,
        "size": 10000 # max size for single page
        }
    header = {'Accept': 'application/json'}
    response = requests.get(URL, auth=HTTPBasicAuth(email, key), params=query_params, headers=header)
    if response.status_code == 200:
        print(f"[+] API call succeeded. Response size: {len(response.json())}")
        return response.json()
    elif response.status_code == 401:
        print("[-] Invalid API credentials. Exiting!")
        exit()
    elif response.status_code == 302:
        print("[-] Invalid API query. Exiting!")
        exit()
    else:
        print("[-] Error during API call.")
        print("[-] " + response.text)
        print("[-] Exiting!")
        exit()

def parse_api_response_euph(api_response_data, unique_users=False, unique_emails=False):
    entries = api_response_data["entries"]
    # print(f"[DEBUG] length of entries is {len(entries)}")
    if len(entries) == 0:
        print("[-] No Results!")
        exit()
    # Preliminary: fill usernames in from email addresses where needed
    for e in entries:
        if e["email"] and e["username"] == '':
            e["username"] = e["email"].split('@')[0]

    # step 1: remove duplicates by username if required
    if unique_users:
        # print("[DEBUG] Entered 'Unique Users' condition")
        seen = set()
        deduplicated_entries = []
        for e in entries:
            key = e["username"].lower()
            if key not in seen:
                seen.add(key)
                deduplicated_entries.append(e)
        entries = deduplicated_entries

    # print(f"[DEBUG] length of entries after username deduplication checks is {len(entries)}")

    # step 2: remove duplicates by username if required
    if unique_emails:
        # print("[DEBUG] Entered 'Unique Emails' condition")
        seen = set()
        deduplicated_entries = []
        for e in entries:
            key = e["email"].lower()
            if key not in seen:
                seen.add(key)
                deduplicated_entries.append(e)
        entries = deduplicated_entries

    # print(f"[DEBUG] length of entries after email deduplication checks is {len(entries)}")

    # step 3: organize entries based on whether they have a password
    password_entries = []
    non_password_entries = []
    for e in entries:
        if e["password"] == '':
            non_password_entries.append(e)
        else:
            password_entries.append(e)
    organized_entries = password_entries + non_password_entries

    # step 4: create and return the parallel lists 
    emails = [entry["email"] for entry in organized_entries]
    passwords = [entry["password"] for entry in organized_entries]
    hashes = [entry["hashed_password"] for entry in organized_entries]
    usernames =  [entry["username"] for entry in organized_entries]


    return emails, usernames, passwords, hashes

def create_file(path):  
    try:        
        f = open(path, 'w')
        return f
        
    except PermissionError:
        print(f"[-] Permission denied: {path}")
        print("[-] Exiting!")
        exit()
    except Exception as e:
        print(f"[-] An error occurred: {e}")
        print("[-] Exiting!")
        exit()

if __name__=="__main__":
    # Setup command line arguments
    parser = argparse.ArgumentParser(description="dehashed-wrapper.py takes care of translating the JSON data from dehashed into simple lists that can be passed to other tools like Burp Suite and Hydra.", add_help=True)
    parser.add_argument("-d", "--domain", required=False, metavar="<domain>", help="The domain to search. Cannot be used with custom query")
    parser.add_argument("-q", "--custom-query", required=False, metavar="<query>", help="Custom Dehashed query. Cannot be used with -d / --domain")
    parser.add_argument("-e", "--email", required=True, metavar="<email>", help="Dehashed account email")
    parser.add_argument("-k", "--api-key", required=True, metavar="<api key>", help="Dehashed API Key")
    parser.add_argument("-uu", "--unique-usernames", required=False, default=False, help="Remove duplicate records by username.", action='store_true')
    parser.add_argument("-ue", "--unique-emails", required=False, default=False, help="Remove duplicate records by email.", action='store_true')

    # Add new formats step 1 / 3
    parser.add_argument("-oU", required=False, metavar="<file>", help="Usernames output file. Parallel order with -oP. Usersnames with no associated password are at the end of the list.")
    parser.add_argument("-oE", required=False, metavar="<file>", help="Emails output file.")
    parser.add_argument("-oP", required=False, metavar="<file>", help="Passwords output file. Parallel with output from oU")
    parser.add_argument("-oUH", required=False, metavar="<file>", help="Output file for colon-delimited usernames and password hashes. username:hash")
    parser.add_argument("-oEH", required=False, metavar="<file>", help="Output file for colon-delimited emails and password hashes. email:hash")
    parser.add_argument("-oUP", required=False, metavar="<file>", help="Output file for colon-delimited usernames and passwords. username:password")
    parser.add_argument("-oEP", required=False, metavar="<file>", help="Output file for colon-delimited emails and passwords. email:password")
    parser.add_argument("-oA", required=False, metavar="<prefix>", help="Output in all formats except 'oPEP'. Argument is file prefix.")
    parser.add_argument("-oPEP", required=False, metavar="<prefix>", help="Parallel Email and Password lists. Argument is file prefix. Not included with -oA.")
    args = parser.parse_args()

    # Make sure a valid combination of arguments is present
    if not (args.domain or args.custom_query):
        print("[-] Domain or custom query required. Exiting!")
        exit()

    if args.domain and args.custom_query:
        print("[-] Multiple queries not supported. Please specify one domain or custom query. Exiting!")
        exit()
    
    # Add new formats step 2 / 3
    if not (args.oU or args.oE or args.oP or args.oUH or args.oEH or args.oUP or args.oEP or args.oA or args.oPEP):
        print("[-] Please Specify an Output Option. Exiting!")
        exit()

    # Call the API 
    print("[+] Calling Dehashed API...")
    if args.domain:
        data = call_api(args.email.lower(), args.api_key.lower(), args.domain)
    else:
        data = call_api(args.email.lower(), args.api_key.lower(), args.custom_query, custom=True)

    # extract parallel data lists
    emails, usernames, passwords, hashes = parse_api_response_euph(data, unique_users=args.unique_usernames, unique_emails=args.unique_emails)

    # Add new formats step 3/3
    if args.oA or args.oU:
        path = args.oA + "-usernames.txt" if args.oA else args.oU
        f = create_file(path)
        for u in usernames:
            if u: f.write(u+"\n")
        f.close()
        print("[+] Created usernames file.")

    if args.oA or args.oE:
        path = args.oA + "-emails.txt" if args.oA else args.oE
        f = create_file(path)
        for e in emails:
            if e: f.write(e+"\n")
        f.close()
        print("[+] Created emails file.")

    if args.oA or args.oP:
        path = args.oA + "-passwords.txt" if args.oA else args.oP
        f = create_file(path)
        for p in passwords:
            if p: f.write(p +"\n")
        f.close()
        print("[+] Created passwords file.")

    if args.oA or args.oUH:
        path = args.oA + "-user-hash.txt" if args.oA else args.oUH
        f = create_file(path)
        for i in range(len(usernames)):
            if usernames[i] and hashes[i]:
                f.write(f"{usernames[i]}:{hashes[i]}\n")
        f.close()
        print("[+] Created user:hash file.")

    if args.oA or args.oEH:
        path = args.oA + "-email-hash.txt" if args.oA else args.oEH
        f = create_file(path)
        for i in range(len(emails)):
            if emails[i] and hashes[i]:
                f.write(f"{emails[i]}:{hashes[i]}\n")
        f.close()
        print("[+] Created email:hash file.")

    if args.oA or args.oUP:
        path = args.oA + "-username-password.txt" if args.oA else args.oUP
        f = create_file(path)
        for i in range(len(usernames)):
            if usernames[i] and passwords[i]:
                f.write(f"{usernames[i]}:{passwords[i]}\n")
        f.close()
        print("[+] Created username:password file.")

    if args.oA or args.oEP:
        path = args.oA + "-email-password.txt" if args.oA else args.oEP
        f = create_file(path)
        for i in range(len(emails)):
            if emails[i] and passwords[i]:
                f.write(f"{emails[i]}:{passwords[i]}\n")
        f.close()
        print("[+] Created email:password file.")

    if args.oPEP:
        email_path = args.oPEP + "-emails.txt"
        password_path = args.oPEP + "-passwords.txt"
        ef = create_file(email_path)
        pf = create_file(password_path)
        for i in range(len(emails)):
            if emails[i] and passwords[i]:
                ef.write(emails[i] + "\n")
                pf.write(passwords[i] + "\n")
        ef.close()
        pf.close()
        print("[+] Created parallel email and password files.")


    print("[+] Completed successfully!")

import tldextract
import argparse
from urllib.parse import urlparse
import sys
import re
import json
from datetime import datetime
from tabulate import tabulate

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

def userInput():
    """
    This function takes user input and returns an args object.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", help="Target domain (eg: example.com)")
    args = parser.parse_args()
    
    return args

def validateDomainCharacters(domain):
    """
    Validates that the domain contains only allowed characters from ASCII or IDN
    """
    # Convert to lowercase (domains are case-insensitive)
    domain_lower = domain.lower()
    
    # Check if it's a pure ASCII domain
    if domain_lower.isascii():
        # only allow a-z, 0-9, hyphen, and dot
        ascii_pattern = re.compile(r'^[a-z0-9\-\.]+$')
        if not ascii_pattern.match(domain_lower):
            print("Invalid characters in domain. ASCII domains can only contain: a-z, 0-9, hyphens (-), and dots (.)")
            sys.exit(1)
    else:
        # Try to convert to Punycode to validate it's a proper IDN
        try:
            # convert Unicode domain to Punycode
            domain_lower.encode('idna')
        except UnicodeError:
            print("Invalid IDN domain. Cannot convert to valid Punycode.")
            sys.exit(1)
    
    return domain_lower

def parseDomain(domain):
    """
    This function parses and validates the domain/user input
    """
    dom = tldextract.extract(domain)
    apex_domain = dom.domain
    subdomain = dom.subdomain
    tld = dom.suffix
    print(f"\nParsed Domain\n=============\nSubdomain: {subdomain}\nApex domain: {apex_domain}\nTop Level Domain: {tld}")
    # validate apex domain exists    
    if not apex_domain or not tld:
        print("please enter a valid domain (Eg: www.example.com)")
        sys.exit(1)
    # validate len
    if len(apex_domain) > 63:
        print("Lenght of apex domain cannot exceed 63 chars")
        sys.exit(1)
    elif apex_domain.startswith("-") or apex_domain.endswith("-") or tld.startswith("-") or tld.endswith("-"):
        print("domain cannot start or end with a hyphen")
        sys.exit(1)
    labels = tld.split(".")
    for x in labels:
        if len(x) > 63:
            print("each label cannot have more than 63 characters")
    if subdomain:
        print(f"Ignoring subdomain: {subdomain}")
    
    parsed_domain = {"subdomain":subdomain, "apex_domain":apex_domain, "tld":tld}
    return parsed_domain

def permutationGenerators(apex_domain):
    """
    This function generates simple permutations of the domain using Omission, Repetition, Transposition, Hyphenation, Vowel swap
    """
    domains = set()

    # Omission
    print(f"Generating permutations using Omissions...\n")
    for index in range(len(apex_domain)):
        if len(apex_domain) <= 2:
            exit
        else:
            domains.add((apex_domain[:index]+apex_domain[index+1:],"omission"))
    
    # Repetition
    print(f"Generating permutations using Repetitions...\n")
    for index in range(len(apex_domain)):
        domains.add((apex_domain[:index]+apex_domain[index]+apex_domain[index:], "repetition"))

    # Transposition
    print(f"Generating permutations using Transpositions...\n")
    if len(apex_domain) > 2:
        for index in range(1, len(apex_domain)-1):
            if apex_domain[:index]+apex_domain[index+1]+apex_domain[index]+apex_domain[index+2:] == apex_domain:
                exit
            else:
                domains.add((apex_domain[:index]+apex_domain[index+1]+apex_domain[index]+apex_domain[index+2:], "transposition"))

    # Hyphenation
    print(f"Generating permutations using Hyphenation...\n")
    if len(apex_domain) == 1:
        exit
    elif len(apex_domain) == 2:
        domains.add((apex_domain[0] + "-" + apex_domain[1], "hyphenation"))
    else:
        for index in range(1, len(apex_domain)):
            # skip if ascii and would create double hyphen
            if apex_domain.isascii() and (apex_domain[index-1] == "-" or apex_domain[index] == "-"):
                continue
            domains.add((apex_domain[:index]+"-"+apex_domain[index:], "hyphenation"))

    # Vowel swapping
    print(f"Generating permutations using Vowel Swapping...\n")
    vowels = ["a", "e", "i", "o", "u"]
    for index in range(len(apex_domain)):
        if apex_domain[index] in vowels:
            for letter in vowels:
                if apex_domain[index] != letter:
                    domains.add((apex_domain[:index] + letter + apex_domain[index+1:], "vowel-swapping"))

    return domains

def keyboardGenerators(apex_domain):
    print(f"Generating permutations using keyboard layout...\n")
    qwertyMap = {
        '1': {'2', 'q', 'w'},
        '2': {'1', '3', 'q', 'w', 'e'},
        '3': {'2', '4', 'w', 'e', 'r'},
        '4': {'3', '5', 'e', 'r', 't'},
        '5': {'4', '6', 'r', 't', 'y'},
        '6': {'5', '7', 't', 'y', 'u'},
        '7': {'6', '8', 'y', 'u', 'i'},
        '8': {'7', '9', 'u', 'i', 'o'},
        '9': {'8', '0', 'i', 'o', 'p'},
        '0': {'9', 'o', 'p'},
        'q': {'1', '2', 'w', 'a', 's'},
        'w': {'1', '2', '3', 'q', 'e', 'a', 's', 'd'},
        'e': {'2', '3', '4', 'w', 'r', 's', 'd', 'f'},
        'r': {'3', '4', '5', 'e', 't', 'd', 'f', 'g'},
        't': {'4', '5', '6', 'r', 'y', 'f', 'g', 'h'},
        'y': {'5', '6', '7', 't', 'u', 'g', 'h', 'j'},
        'u': {'6', '7', '8', 'y', 'i', 'h', 'j', 'k'},
        'i': {'7', '8', '9', 'u', 'o', 'j', 'k', 'l'},
        'o': {'8', '9', '0', 'i', 'p', 'k', 'l'},
        'p': {'9', '0', 'o', 'l'},
        'a': {'q', 'w', 's', 'z', 'x'},
        's': {'q', 'w', 'e', 'a', 'd', 'z', 'x', 'c'},
        'd': {'w', 'e', 'r', 's', 'f', 'x', 'c', 'v'},
        'f': {'e', 'r', 't', 'd', 'g', 'c', 'v', 'b'},
        'g': {'r', 't', 'y', 'f', 'h', 'v', 'b', 'n'},
        'h': {'t', 'y', 'u', 'g', 'j', 'b', 'n', 'm'},
        'j': {'y', 'u', 'i', 'h', 'k', 'n', 'm'},
        'k': {'u', 'i', 'o', 'j', 'l', 'm'},
        'l': {'i', 'o', 'p', 'k'},
        'z': {'a', 's', 'x'},
        'x': {'a', 's', 'd', 'z', 'c'},
        'c': {'s', 'd', 'f', 'x', 'v'},
        'v': {'d', 'f', 'g', 'c', 'b'},
        'b': {'f', 'g', 'h', 'v', 'n'},
        'n': {'g', 'h', 'j', 'b', 'm'},
        'm': {'h', 'j', 'k', 'n'},
    }

    azertyMap = {
        '1': {'2', 'a', 'z'},
        '2': {'1', '3', 'a', 'z', 'e'},
        '3': {'2', '4', 'z', 'e', 'r'},
        '4': {'3', '5', 'e', 'r', 't'},
        '5': {'4', '6', 'r', 't', 'y'},
        '6': {'5', '7', 't', 'y', 'u'},
        '7': {'6', '8', 'y', 'u', 'i'},
        '8': {'7', '9', 'u', 'i', 'o'},
        '9': {'8', '0', 'i', 'o', 'p'},
        '0': {'9', 'o', 'p'},
        'a': {'1', '2', 'z', 'q', 's'},
        'z': {'1', '2', '3', 'a', 'e', 'q', 's', 'd'},
        'e': {'2', '3', '4', 'z', 'r', 's', 'd', 'f'},
        'r': {'3', '4', '5', 'e', 't', 'd', 'f', 'g'},
        't': {'4', '5', '6', 'r', 'y', 'f', 'g', 'h'},
        'y': {'5', '6', '7', 't', 'u', 'g', 'h', 'j'},
        'u': {'6', '7', '8', 'y', 'i', 'h', 'j', 'k'},
        'i': {'7', '8', '9', 'u', 'o', 'j', 'k', 'l'},
        'o': {'8', '9', '0', 'i', 'p', 'k', 'l', 'm'},
        'p': {'9', '0', 'o', 'l', 'm'},
        'q': {'a', 'z', 's', 'w', 'x'},
        's': {'a', 'z', 'e', 'q', 'd', 'w', 'x', 'c'},
        'd': {'z', 'e', 'r', 's', 'f', 'x', 'c', 'v'},
        'f': {'e', 'r', 't', 'd', 'g', 'c', 'v', 'b'},
        'g': {'r', 't', 'y', 'f', 'h', 'v', 'b', 'n'},
        'h': {'t', 'y', 'u', 'g', 'j', 'b', 'n'},
        'j': {'y', 'u', 'i', 'h', 'k', 'n'},
        'k': {'u', 'i', 'o', 'j', 'l'},
        'l': {'i', 'o', 'p', 'k', 'm'},
        'm': {'o', 'p', 'l'},
        'w': {'q', 's', 'x'},
        'x': {'q', 's', 'd', 'w', 'c'},
        'c': {'s', 'd', 'f', 'x', 'v'},
        'v': {'d', 'f', 'g', 'c', 'b'},
        'b': {'f', 'g', 'h', 'v', 'n'},
        'n': {'g', 'h', 'j', 'b'},
    }

    qwertzMap = {
        '1': {'2', 'q', 'w'},
        '2': {'1', '3', 'q', 'w', 'e'},
        '3': {'2', '4', 'w', 'e', 'r'},
        '4': {'3', '5', 'e', 'r', 't'},
        '5': {'4', '6', 'r', 't', 'z'},
        '6': {'5', '7', 't', 'z', 'u'},
        '7': {'6', '8', 'z', 'u', 'i'},
        '8': {'7', '9', 'u', 'i', 'o'},
        '9': {'8', '0', 'i', 'o', 'p'},
        '0': {'9', 'o', 'p'},
        'q': {'1', '2', 'w', 'a', 's'},
        'w': {'1', '2', '3', 'q', 'e', 'a', 's', 'd'},
        'e': {'2', '3', '4', 'w', 'r', 's', 'd', 'f'},
        'r': {'3', '4', '5', 'e', 't', 'd', 'f', 'g'},
        't': {'4', '5', '6', 'r', 'z', 'f', 'g', 'h'},
        'z': {'5', '6', '7', 't', 'u', 'g', 'h', 'j'},
        'u': {'6', '7', '8', 'z', 'i', 'h', 'j', 'k'},
        'i': {'7', '8', '9', 'u', 'o', 'j', 'k', 'l'},
        'o': {'8', '9', '0', 'i', 'p', 'k', 'l'},
        'p': {'9', '0', 'o', 'l'},
        'a': {'q', 'w', 's', 'y', 'x'},
        's': {'q', 'w', 'e', 'a', 'd', 'y', 'x', 'c'},
        'd': {'w', 'e', 'r', 's', 'f', 'x', 'c', 'v'},
        'f': {'e', 'r', 't', 'd', 'g', 'c', 'v', 'b'},
        'g': {'r', 't', 'z', 'f', 'h', 'v', 'b', 'n'},
        'h': {'t', 'z', 'u', 'g', 'j', 'b', 'n', 'm'},
        'j': {'z', 'u', 'i', 'h', 'k', 'n', 'm'},
        'k': {'u', 'i', 'o', 'j', 'l', 'm'},
        'l': {'i', 'o', 'p', 'k'},
        'y': {'a', 's', 'x'},
        'x': {'a', 's', 'd', 'y', 'c'},
        'c': {'s', 'd', 'f', 'x', 'v'},
        'v': {'d', 'f', 'g', 'c', 'b'},
        'b': {'f', 'g', 'h', 'v', 'n'},
        'n': {'g', 'h', 'j', 'b', 'm'},
        'm': {'h', 'j', 'k', 'n'},
    }

    domains = set()

    # generate variants for QWERTY
    for i,char in enumerate(apex_domain):
        for key in qwertyMap.keys():
            if char == key:
                for vals in qwertyMap[key]:
                    domains.add((apex_domain[:i] + vals + apex_domain[i+1:], "qwerty-generator"))

    # generate variants for AZERTY
    for i,char in enumerate(apex_domain):
        for key in azertyMap.keys():
            if char == key:
                for vals in azertyMap[key]:
                    domains.add((apex_domain[:i] + vals + apex_domain[i+1:], "azerty-generator"))

    # generate variants for QWERTZ
    for i,char in enumerate(apex_domain):
        for key in qwertzMap.keys():
            if char == key:
                for vals in qwertzMap[key]:
                    domains.add((apex_domain[:i] + vals + apex_domain[i+1:], "qwertz-generator"))

    return domains

def homoglyphGenerators(apex_domain):
    print(f"Generating permutations using Homoglyphs...\n")
    domains = set()
    cyrillic_greek = {
        'a': ['а', 'α'],  # Cyrillic а, Greek alpha
        'c': ['с'],       # Cyrillic с
        'e': ['е'],       # Cyrillic е
        'h': ['һ'],       # Cyrillic һ
        'i': ['і', 'ι'],  # Cyrillic і, Greek iota
        'j': ['ј'],       # Cyrillic ј
        'k': ['к', 'κ'],  # Cyrillic к, Greek kappa
        'l': ['ӏ'],       # Cyrillic palochka
        'o': ['о', 'ο'],  # Cyrillic о, Greek omicron
        'p': ['р', 'ρ'],  # Cyrillic р, Greek rho
        'q': ['ԛ'],       # Cyrillic ԛ
        's': ['ѕ'],       # Cyrillic ѕ
        'u': ['υ'],       # Greek upsilon
        'v': ['ν'],       # Greek nu
        'x': ['х', 'χ'],  # Cyrillic х, Greek chi
        'y': ['у', 'γ'],  # Cyrillic у, Greek gamma
    }

    homoglyphs = {
        'a': ['а', 'à', 'á', 'â', 'ã', 'ä', 'å', 'ā', 'ą'],
        'b': ['ḃ', 'ḅ', '6'],
        'c': ['с', 'ç', 'ć', 'ĉ', 'ċ'],
        'd': ['ḋ', 'ḍ'],
        'e': ['е', 'è', 'é', 'ê', 'ë', 'ē', 'ė', 'ę'],
        'f': ['ḟ'],
        'g': ['ġ', 'ģ', '9'],
        'h': ['һ', 'ḣ', 'ḥ'],
        'i': ['і', 'ì', 'í', 'î', 'ï', 'ī', 'į', '1', 'l'],
        'j': ['ј'],
        'k': ['ķ', 'ḳ'],
        'l': ['1', 'i', 'ӏ'],
        'm': ['ṁ', 'ṃ'],
        'n': ['ñ', 'ń', 'ņ', 'ṅ', 'ṇ'],
        'o': ['о', 'ο', 'ò', 'ó', 'ô', 'õ', 'ö', 'ō', '0'],
        'p': ['р', 'ṗ'],
        'q': ['ԛ'],
        'r': ['ṙ', 'ṛ'],
        's': ['ѕ', 'ś', 'ş', 'š', 'ṡ', '5'],
        't': ['ṫ', 'ṭ'],
        'u': ['ù', 'ú', 'û', 'ü', 'ū', 'ů'],
        'v': ['ν', 'ṿ'],
        'w': ['ẁ', 'ẃ', 'ẅ', 'ẇ'],
        'x': ['х', 'ẋ', 'ẍ'],
        'y': ['у', 'ý', 'ÿ', 'ŷ', 'ẏ'],
        'z': ['ź', 'ż', 'ž', 'ẓ', '2'],
    }

    # replace single char at a time
    for i,char in enumerate(apex_domain):
        for key in homoglyphs.keys():
            if char == key:
                for value in homoglyphs[key]:
                    temp_domain = apex_domain[:i]+value+apex_domain[i+1:]
                    punycode = temp_domain.encode('idna').decode('ascii')
                    domains.add((temp_domain, punycode, "homoglyphs"))


    # Check if all chars have cyrillic/greek equivalent using consolidated dictionary
    all_chars_have_equivalent = True
    for char in apex_domain:
        if char not in cyrillic_greek:
            all_chars_have_equivalent = False
            break

    if all_chars_have_equivalent:
        combinations = [""]
        
        for char in apex_domain:
            new_combinations = []
            for combo in combinations:
                for value in cyrillic_greek[char]:
                    new_combinations.append(combo + value)
            combinations = new_combinations
        
        # Add all combinations to domain set
        for substituted_domain in combinations:
            punycode = substituted_domain.encode('idna').decode('ascii')
            domains.add((substituted_domain, punycode, "cyrillic_greek"))
    
    return domains

def combosquatGenerators(apex_domain):
    print(f"Generating permutations using Combosquatting...\n")
    domains = set()
    prefix_suffix = [
        "login",
        "signin",
        "sign-in",
        "logon",
        "log-in",
        "signon",
        "sign-on",
        "auth",
        "authenticate",
        "authentication",
        "password",
        "account",
        "accounts",
        "myaccount",
        "my-account",
        "user",
        "users",
        "profile",
        "member",
        "members",
        "membership",
        "customer",
        "customers",
        "secure",
        "security",
        "secured",
        "verify",
        "verification",
        "verified",
        "confirm",
        "confirmation",
        "validate",
        "validation",
        "authenticate",
        "2fa",
        "mfa",
        "protect",
        "protected",
        "protection",
        "alert",
        "alerts",
        "warning",
        "support",
        "supports",
        "help",
        "helpdesk",
        "help-desk",
        "service",
        "services",
        "customer-service",
        "customerservice",
        "care",
        "customercare",
        "customer-care",
        "contact",
        "assist",
        "assistance",
        "official",
        "corp",
        "corporate",
        "inc",
        "company",
        "enterprise",
        "business",
        "www",
        "web",
        "online",
        "site",
        "portal",
        "page",
        "home",
        "homepage",
        "get",
        "my",
        "update",
        "updates",
        "upgrade",
        "renew",
        "renewal",
        "restore",
        "recover",
        "recovery",
        "reset",
        "change",
        "manage",
        "review",
        "check",
        "access",
        "unlock",
        "activate",
        "reactivate",
        "claim",
        "pay",
        "payment",
        "payments",
        "billing",
        "bill",
        "invoice",
        "invoices",
        "order",
        "orders",
        "checkout",
        "cart",
        "wallet",
        "card",
        "credit",
        "refund",
        "status",
        "alert",
        "alerts",
        "notification",
        "notifications",
        "notify",
        "notice",
        "info",
        "information",
        "message",
        "messages",
        "center",
        "centre",
        "hub",
        "us",
        "usa",
        "uk",
        "eu",
        "asia",
        "global",
        "international",
        "local",
    ]

    for word in prefix_suffix:
        domains.add((word+"-"+apex_domain, "combosquatting"))
        domains.add((apex_domain+"-"+word, "combosquatting"))

    return domains

def tldGenerators(tld):
    tld_list = [tld]
    tlds = [
        ".cm",
        ".co",
        ".om",
        ".net",
        ".org",
        ".online",
        ".io",
        ".app",
        # Country-specific TLDs
        ".in",
        ".us",
        ".uk",
        ".de",
        ".fr",
        ".es",
        ".it",
        ".nl",
        ".au",
        ".ca",
        ".br",
        ".mx",
        ".jp",
        ".cn",
        ".ru",
        ".pl",
        ".se",
        ".no",
        ".dk",
        ".fi",
        ".be",
        ".at",
        ".ch",
        ".nz",
        ".sg",
        ".hk",
        ".kr",
        ".tw",
        ".za",
        ".ae",
        ".sa",
    ]

    for t in tlds:
        tld_list.append(t)
    
    return tld_list

def genDomains(domain_dict):
    """
    This function orchestrates the domains generated by the tool.
    Returns set of tuples: (full_domain, punycode_domain, method, tld_suffix)
    """
    apex_domain = domain_dict["apex_domain"]
    tld = domain_dict["tld"]
    perms = permutationGenerators(apex_domain)
    keyboards = keyboardGenerators(apex_domain)
    homos = homoglyphGenerators(apex_domain)
    combsquat = combosquatGenerators(apex_domain)
    tldlist = tldGenerators(tld)

    normalized_apex = set()

    # Fix: Union all generators (perms, keyboards, combsquat return 2-tuples)
    all_two_tuple_gens = perms | keyboards | combsquat
    for apex, method in all_two_tuple_gens:
        try:
            punycode = apex.encode('idna').decode('ascii')
        except (UnicodeError, UnicodeDecodeError):
            punycode = apex
        normalized_apex.add((apex, punycode, method))

    # Homoglyphs already return 3-tuples (apex, punycode, method)
    normalized_apex.update(homos)

    final_domains = set()
    for apex, punycode, method in normalized_apex:
        for tld_suffix in tldlist:
            if not tld_suffix.startswith("."):
                tld_suffix = "." + tld_suffix
            fulldom = f"{apex}{tld_suffix}"
            fullpuny = f"{punycode}{tld_suffix}"
            # Include tld_suffix for scoring purposes
            final_domains.add((fulldom, fullpuny, method, tld_suffix))
    
    print("\n=====AGGREGATED DOMAINS=====\n")
    print(f"Total unique domains generated: {len(final_domains)}")
    return final_domains

def levenshteinDistance(s1, s2):
    """
    Calculate the Levenshtein distance between two strings.
    """
    if len(s1) < len(s2):
        return levenshteinDistance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            # insertions, deletions, substitutions
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

def calculateSimilarityScore(original_str, generated_str):
    """
    Calculate normalized similarity score (0-1 scale).
    1.0 = identical, 0.0 = completely different
    """
    distance = levenshteinDistance(original_str, generated_str)
    max_len = max(len(original_str), len(generated_str))
    if max_len == 0:
        return 1.0
    similarity = 1 - (distance / max_len)
    return similarity

def getMethodRiskWeight(method):
    """
    Returns a risk weight multiplier based on the deception method.
    Higher weight = more deceptive/risky.
    """
    method_weights = {
        # Homoglyphs are most deceptive - visually identical
        "homoglyphs": 1.0,
        "cyrillic_greek": 1.0,
        # Single character changes - very deceptive
        "omission": 0.95,
        "repetition": 0.95,
        "transposition": 0.90,
        "vowel-swapping": 0.85,
        # Keyboard typos - common mistakes
        "qwerty-generator": 0.80,
        "azerty-generator": 0.80,
        "qwertz-generator": 0.80,
        # Hyphenation - moderately deceptive
        "hyphenation": 0.70,
        # Combosquatting - adds words, less similar but still risky
        "combosquatting": 0.60,
    }
    return method_weights.get(method, 0.5)

def getTLDSimilarityScore(original_tld, generated_tld):
    """
    Calculate TLD similarity score using Levenshtein distance.
    Same TLD = 1.0, similar TLDs score higher than dissimilar ones.
    """
    # Normalize TLDs (remove leading dot)
    orig = original_tld.lstrip(".")
    gen = generated_tld.lstrip(".")
    
    # Exact match
    if orig == gen:
        return 1.0
    
    # Use Levenshtein-based similarity for TLDs
    tld_similarity = calculateSimilarityScore(orig, gen)
    
    # Boost score for popular/trusted TLDs (more likely to be targeted)
    trusted_tlds = {"com", "net", "org", "io", "co", "app", "dev"}
    if orig in trusted_tlds and gen in trusted_tlds:
        # Both are trusted TLDs - slightly higher risk
        return max(tld_similarity, 0.70)
    
    return tld_similarity

def scoreDomains(original_domain, original_tld, final_domains):
    """
    Score all generated domains and return sorted by risk (highest similarity first).
    Composite score = (apex_similarity * 0.5) + (tld_similarity * 0.3) + (method_weight * 0.2)
    Returns list of dicts with domain info and scores.
    """
    scored_domains = []
    for domain, punycode, method, tld_suffix in final_domains:
        # Extract just the apex domain part for comparison
        dom_extract = tldextract.extract(domain)
        apex_only = dom_extract.domain
        
        # Calculate component scores
        apex_similarity = calculateSimilarityScore(original_domain, apex_only)
        tld_similarity = getTLDSimilarityScore(original_tld, tld_suffix)
        method_weight = getMethodRiskWeight(method)
        
        # Composite score with weighted components
        # Apex similarity is most important (50%), TLD matters (30%), method risk (20%)
        composite_score = (apex_similarity * 0.5) + (tld_similarity * 0.3) + (method_weight * 0.2)
        
        scored_domains.append({
            "domain": domain,
            "punycode": punycode,
            "method": method,
            "similarity_score": round(composite_score, 4),
            "apex_similarity": round(apex_similarity, 4),
            "tld_similarity": round(tld_similarity, 4),
            "method_weight": round(method_weight, 4)
        })
    
    # Sort by composite similarity score (highest risk first)
    scored_domains.sort(key=lambda x: x["similarity_score"], reverse=True)
    return scored_domains

def formatOutputJSON(scored_domains, original_domain, output_file):
    """
    Format and save results as JSON.
    """
    output_data = {
        "scan_info": {
            "original_domain": original_domain,
            "scan_timestamp": datetime.now().isoformat(),
            "total_domains_generated": len(scored_domains)
        },
        "domains": scored_domains
    }
    
    json_filename = f"{output_file}.json"
    with open(json_filename, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    print(f"JSON output saved to: {json_filename}")
    return json_filename

def displayTopResults(scored_domains, original_domain, top_n=50):
    """
    Display top N results in a pretty table format in terminal using tabulate.
    """
    print(f"\n{Colors.BOLD}{Colors.CYAN}TOP {top_n} HIGH-RISK DOPPELGANGER DOMAINS{Colors.RESET}")
    print(f"Target: {Colors.YELLOW}{original_domain}{Colors.RESET}\n")
    
    # Prepare table data
    table_data = []
    for i, d in enumerate(scored_domains[:top_n], 1):
        domain = d['domain']
        method = d['method']
        score = d['similarity_score']
        
        # Truncate domain if too long
        if len(domain) > 40:
            domain = domain[:37] + "..."
        
        # Color code based on score
        if score >= 0.9:
            score_str = f"{Colors.RED}{score:.4f}{Colors.RESET}"
        elif score >= 0.8:
            score_str = f"{Colors.YELLOW}{score:.4f}{Colors.RESET}"
        else:
            score_str = f"{Colors.GREEN}{score:.4f}{Colors.RESET}"
        
        table_data.append([i, domain, method, score_str])
    
    headers = [f"{Colors.BOLD}#{Colors.RESET}", 
               f"{Colors.BOLD}Domain{Colors.RESET}", 
               f"{Colors.BOLD}Method{Colors.RESET}", 
               f"{Colors.BOLD}Score{Colors.RESET}"]
    
    print(tabulate(table_data, headers=headers, tablefmt="rounded_grid"))
    
    # Summary
    print(f"\n{Colors.DIM}Showing top {top_n} of {len(scored_domains)} total domains generated{Colors.RESET}")

def saveOutputs(scored_domains, original_domain):
    """
    Save outputs to JSON file.
    """
    # Generate output filename based on domain and timestamp
    safe_domain = original_domain.replace(".", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"doppelganger_{safe_domain}_{timestamp}"
    
    json_file = formatOutputJSON(scored_domains, original_domain, output_file)
    
    return json_file

def main():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
┳┓       •    ┳┓        ┓              
┃┃┏┓┏┳┓┏┓┓┏┓  ┃┃┏┓┏┓┏┓┏┓┃┏┓┏┓┏┓┏┓┏┓┏┓  
┻┛┗┛┛┗┗┗┻┗┛┗  ┻┛┗┛┣┛┣┛┗ ┗┗┫┗┻┛┗┗┫┗ ┛   
                  ┛ ┛     ┛     ┛      
{Colors.RESET}
    {Colors.DIM}by- https://github.com/RIZZZIOM{Colors.RESET}
    """
    print(banner)

    cmd = userInput()
    domain = cmd.domain.strip()
    
    # validate it is not a URL and doesn't contain schema
    if "/" in domain or ":" in domain:
        print(f"{Colors.RED}✗ Error: Please enter a valid domain (Eg: example.com){Colors.RESET}")
        sys.exit(1)
    
    # Character Validation
    print(f"{Colors.CYAN}[*]{Colors.RESET} Validating domain...")
    valid_domain = validateDomainCharacters(domain)
    
    print(f"{Colors.CYAN}[*]{Colors.RESET} Parsing domain...")
    domain_dict = parseDomain(valid_domain)
    
    print(f"\n{Colors.CYAN}[*]{Colors.RESET} Generating domain variations...")
    all_domains = genDomains(domain_dict)
    
    # Score domains by similarity
    print(f"{Colors.CYAN}[*]{Colors.RESET} Scoring domains by similarity...")
    original_apex = domain_dict["apex_domain"]
    original_tld = domain_dict["tld"]
    scored_domains = scoreDomains(original_apex, original_tld, all_domains)
    
    # Display top results in terminal
    full_original = f"{domain_dict['apex_domain']}.{domain_dict['tld']}"
    displayTopResults(scored_domains, full_original, top_n=50)
    
    # Save outputs
    print(f"\n{Colors.CYAN}[*]{Colors.RESET} Saving results...")
    json_file = saveOutputs(scored_domains, full_original)
    print(f"{Colors.GREEN}✓ Results saved to: {json_file}{Colors.RESET}")
    print(f"\n{Colors.GREEN}{Colors.BOLD}Scan complete!{Colors.RESET}\n")

if __name__ == "__main__":
    main()
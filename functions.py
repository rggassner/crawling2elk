import hashlib
import json
import os
import random
import re
import string
import time
from config import *
from datetime import datetime, timezone
from elasticsearch import NotFoundError, RequestError, Elasticsearch
from elasticsearch import ConflictError
from elasticsearch.exceptions import NotFoundError, RequestError
from urllib.parse import urlsplit, urlunsplit, unquote, parse_qs


# Class for managing a connection to an Elasticsearch cluster
class DatabaseConnection:
    """
    A wrapper class for managing an Elasticsearch connection using the official Elasticsearch client.

    This class mimics a standard database interface, providing compatibility with systems
    that expect methods like `commit`, `close`, `search`, and `scroll`.

    Attributes:
        es (Elasticsearch): The initialized Elasticsearch client.
        con (Elasticsearch): Alias for `es`, for compatibility with database-like interfaces.
    """
    def __init__(self):
        # Prepare configuration for Elasticsearch connection
        es_config = {
            "hosts": [f"https://{ELASTICSEARCH_HOST}:{ELASTICSEARCH_PORT}"],
            "basic_auth": (ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD),
            "verify_certs": ELASTICSEARCH_VERIFY_CERTS,
            "request_timeout": ELASTICSEARCH_TIMEOUT,
            "retry_on_timeout": ELASTICSEARCH_RETRY,
            "max_retries": ELASTICSEARCH_RETRIES,
            "http_compress": ELASTICSEARCH_HTTP_COMPRESS
        }

        # If a custom CA certificate path is provided, add it to the config for certificate verification
        if ELASTICSEARCH_CA_CERT_PATH:
            es_config["ca_certs"] = ELASTICSEARCH_CA_CERT_PATH

        # Initialize Elasticsearch client with the config
        self.es = Elasticsearch(**es_config)

        # Optional alias to keep compatibility with interfaces expecting `self.con`
        self.con = self.es

    def commit(self):
        # Placeholder method – does nothing
        # Included for interface compatibility with other DB connectors (e.g., SQL)
        pass

    def close(self):
        # Properly close the Elasticsearch connection
        self.es.close()

    def search(self, *args, **kwargs):
        # Wrapper around the `search` method of the Elasticsearch client
        # Allows flexible usage with both positional and keyword arguments
        return self.es.search(*args, **kwargs)

    def scroll(self, *args, **kwargs):
        # Wrapper for the `scroll` API, used for paginating large result sets
        return self.es.scroll(*args, **kwargs)


def sanitize_url(
        url,
        debug=True,
        skip_log_tags=['FINAL_NORMALIZE',
                       'STRIP_WHITESPACE',
                       'NORMALIZE_PATH_SLASHES']):
    """
    Sanitize and normalize a given URL by cleaning common formatting issues and typos.

    This function performs a series of transformations to correct malformed URLs:
    - Removes surrounding quotes and special quote characters.
    - Fixes common protocol typos (e.g. `htpp://`, `ttps://`, etc.).
    - Trims whitespace and normalizes redundant slashes in paths.
    - Validates and cleans hostnames and ports, including `username:password@host:port`.
    - Rebuilds the URL using standard components if parsing is successful.
    - Falls back to basic string cleanup if parsing fails.

    Optionally logs each transformation step unless the change type is listed in
    `skip_log_tags`.

    Args:
        url (str): The raw URL string to sanitize.
        debug (bool): If True, logs detected changes using ANSI-colored output.
        skip_log_tags (list[str]): A list of change reasons (tags) to suppress logging for.

    Returns:
        str: The sanitized and normalized URL string. If the input is invalid, an empty
        string or minimally cleaned version may be returned.
    """

    if skip_log_tags is None:
        skip_log_tags = set()

    def log_change(reason, before, after):
        if before != after and reason not in skip_log_tags and debug:
            print(f"\033[91m[{reason}] URL sanitized \
                  from -{before}- to -{after}-\033[00m")

    def clean_hostname_with_userinfo(netloc, scheme):
        """
        Cleans netloc, preserving valid username:password@host:port
        patterns. Removes invalid characters, strips default ports, and
        validates port range.
        """
        userinfo = ''
        host_port = netloc

        if '@' in netloc:
            userinfo, host_port = netloc.split('@', 1)
            # Clean userinfo (basic, do not over-sanitize)
            userinfo = ''.join(c for c in userinfo if c.isprintable())

        if ':' in host_port:
            host, port = host_port.rsplit(':', 1)
            host = ''.join(c for c in host if c.isalnum() or c in '-.')
            if port.isdigit():
                port_num = int(port)
                if (scheme == 'http' and port == '80') or \
                        (scheme == 'https' and port == '443'):
                    port = ''
                elif 1 <= port_num <= 65535:
                    pass  # valid
                else:
                    port = ''
            else:
                port = ''
        else:
            host = ''.join(c for c in host_port if c.isalnum() or c in '-.')
            port = ''

        result = host
        if port:
            result += f':{port}'
        if userinfo:
            result = f'{userinfo}@{result}'
        return result

    def safe_normalize_path_slashes(path):
        # Split on any embedded full http(s) URL and keep them intact
        segments = re.split(r'(/https?://)', path)
        result = []
        for i in range(0, len(segments), 2):
            part = segments[i]
            part = re.sub(r'/{2,}', '/', part)
            result.append(part)
            if i + 1 < len(segments):
                # re-append the "/https://" or "/http://"
                result.append(segments[i + 1])
        return ''.join(result)

    pre_sanitize = url
    if not url or not isinstance(url, str):
        return ""

    url = url.strip()
    log_change("STRIP_WHITESPACE", pre_sanitize, url)
    pre_sanitize = url
    special_quote_pairs = [
        (r'^"(.*)"$', r'\1'),
        (r"^'(.*)'$", r'\1'),
        (r'^\u201C(.*)\u201D$', r'\1'),
        (r'^\u2018(.*)\u2019$', r'\1'),
        (r'^"(.*)″$', r'\1'),
    ]
    for pattern, replacement in special_quote_pairs:
        cleaned = re.sub(pattern, replacement, url)
        log_change("SPECIAL_QUOTE_CLEAN", url, cleaned)
        url = cleaned

    scheme_fixes = [
        (r'^ps://', 'https://'), (r'^ttps://', 'https://'),
        (r'^htpps://', 'https://'), (r'^httpp://', 'https://'),
        (r'^http:s//', 'https://'), (r'^hthttps://', 'https://'),
        (r'^httsp://', 'https://'), (r'^htts://', 'https://'),
        (r'^htttps://', 'https://'), (r'^https:https://', 'https://'),
        (r'^https https://', 'https://'), (r'^httpshttps://', 'https://'),
        (r'^https://https://', 'https://'), (r'^"https://', 'https://'),
        (r'^httpd://', 'https://'), (r'^htps://', 'https://'),
        (r'^https: //', 'https://'), (r'^https : //', 'https://'),
        (r'^http2://', 'https://'), (r'^https%3A//', 'https://'),
        (r'^%20https://', 'https://'), (r'^htto://', 'http://'),
        (r'^htt://', 'http://'), (r'^htp://http//', 'http://'),
        (r'^htp://', 'http://'), (r'^hhttp://', 'http://'),
        (r'^http:/http://', 'http://'), (r'^http:www', 'http://www'),
        (r'^htttp://', 'http://'), (r'^ttp://', 'http://'),
        (r'^%20http://', 'http://'), (r'^%22mailto:', 'mailto:'),
        (r'^httpqs://', 'https://www.'), (r'^://', 'https://')
    ]
    for pattern, replacement in scheme_fixes:
        fixed = re.sub(pattern, replacement, url)
        log_change("FIX_SCHEME", url, fixed)
        url = fixed

    cleaned = re.sub(r'^[a-zA-Z."(´]https://', 'https://', url)
    log_change("PREFIX_CLEAN_HTTPS", url, cleaned)
    url = cleaned
    cleaned = re.sub(r'^[a-zA-Z."(´]http://', 'http://', url)
    log_change("PREFIX_CLEAN_HTTP", url, cleaned)
    url = cleaned

    url = re.sub(r'^(https?:)/+', r'\1//', url)
    log_change("FIX_SCHEME_SLASHES", pre_sanitize, url)
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        netloc = clean_hostname_with_userinfo(parsed.netloc, scheme)

        if not netloc and parsed.path.startswith('/') and scheme:
            parts = parsed.path.lstrip('/').split('/', 1)
            if parts and '.' in parts[0]:
                netloc = clean_hostname_with_userinfo(parts[0], scheme)
                path = '/' + (parts[1] if len(parts) > 1 else '')
                rebuilt = urlunsplit(
                        (scheme,
                         netloc,
                         path,
                         parsed.query,
                         parsed.fragment))
                log_change("FIX_NETLOC_IN_PATH", url, rebuilt)
                url = rebuilt
        else:
            path = re.sub(r'/{2,}', '/', parsed.path)
            rebuilt = urlunsplit(
                    (scheme,
                     netloc,
                     path,
                     parsed.query,
                     parsed.fragment))
            log_change("NORMALIZE_PATH_SLASHES", url, rebuilt)
            url = rebuilt
    except Exception:
        fallback = re.sub(r'(https?://[^/]+)/{2,}', r'\1/', url)
        log_change("FALLBACK_SLASH_FIX", url, fallback)
        url = fallback

    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()

        if ':' in netloc:
            host, port = netloc.split(':', 1)
            if (
                    (scheme == 'http' and port == '80') or
                    (scheme == 'https' and port == '443')
               ):
                netloc = host

        path = safe_normalize_path_slashes(parsed.path)
        normalized = urlunsplit((scheme, netloc, path, parsed.query, ''))
        log_change("FINAL_NORMALIZE", url, normalized)
        return normalized.strip()
    except Exception:
        return url.strip()


def hash_url(url):
    """
    Generate a SHA-256 hash of a given URL string.

    This function encodes the URL using UTF-8 and returns its SHA-256
    hexadecimal digest. It's useful for uniquely identifying or indexing URLs
    without storing the full plain text.

    Args:
        url (str): The URL string to be hashed.

    Returns:
        str: The hexadecimal representation of the SHA-256 hash of the URL.
    """
    return hashlib.sha256(url.encode('utf-8')).hexdigest()


def remove_jsessionid_with_semicolon(url):
    """
    Remove Java session identifiers from URLs.

    Specifically removes `;jsessionid=...` fragments that are often
    appended to URLs by Java-based web applications to track sessions
    without cookies.

    Args:
        url (str): The input URL possibly containing a `;jsessionid=` parameter.

    Returns:
        str: The URL with any `;jsessionid=...` segment removed.
    """
    pattern = r';jsessionid=[^&?]*'
    cleaned_url = re.sub(pattern, '', url)
    return cleaned_url


def db_create_database(initial_url, db):
    """
    Create the Elasticsearch index structure used for storing crawled URLs,
    and insert the initial seed URL if the index does not already exist.

    This function defines the mapping (schema) for the `URLS_INDEX`, which includes
    various metadata fields used during web crawling such as directory levels,
    content type, whether the URL has been visited, open directory indicators, etc.

    It creates the index if it doesn't already exist, and inserts the initial URL
    as the first entry to kick off crawling.

    Args:
        initial_url (str): The initial URL to insert into the database.
        db (object): A database wrapper that provides access to the Elasticsearch client
                     (via `db.con`) and helper functions like `db_insert_if_new_url`.

    Returns:
        bool: True if the index was created or already existed and the insertion was attempted successfully,
              False if there was an error during index creation or document insertion.
    """
    print("Creating Elasticsearch index structure.")
    now_iso = datetime.now(timezone.utc).isoformat()

    # Define mappings for the URLS_INDEX
    urls_mapping = {
        "mappings": {
            "properties": {
                "url": {"type": "keyword"},
                "visited": {"type": "boolean"},
                "fast_crawled": {"type": "boolean"},
                "isopendir": {"type": "boolean"},
                "isnsfw": {"type": "float"},
                "content_type": {"type": "keyword"},
                "source": {"type": "keyword"},
                "words": {"type": "keyword"},
                "host": {"type": "keyword"},
                "parent_host": {"type": "keyword"},
                "host_levels": {"type": "keyword"},
                "directory_levels": {"type": "keyword"},
                "file_extension": {"type": "keyword"},
                "has_query": {"type": "boolean"},
                "query_variables": {"type": "keyword"},
                "query_values": {"type": "keyword"},
                # Dynamically add keyword fields for directory level depth
                **{
                    f"directory_level_{i+1}": {"type": "keyword"}
                    for i in range(MAX_DIR_LEVELS)
                },
                # Dynamically add keyword fields for host level depth
                **{
                    f"host_level_{i+1}": {"type": "keyword"}
                    for i in range(MAX_HOST_LEVELS)
                },
                "emails": {"type": "keyword"},
                "resolution": {"type": "integer"},
                "random_bucket": {"type": "integer"},
                "created_at": {"type": "date"},
                "updated_at": {"type": "date"},
                "opendir_category": {"type": "keyword"},
                "min_webcontent": {"type": "text"},
                "raw_webcontent": {"type": "text"}
            }
        }
    }

    try:
        # Create index if it does not exist
        if not db.con.indices.exists(index=URLS_INDEX):
            db.con.indices.create(index=URLS_INDEX, body=urls_mapping)
            print("Created {} index.".format(URLS_INDEX))

            # Insert the initial URL into the index to bootstrap crawling
            db_insert_if_new_url(
                url=initial_url,
                source='db_create_database',
                parent_host=urlsplit(initial_url)[1],
                db=db
            )
            print("Inserted initial url {}.".format(initial_url))

        return True
    except Exception as e:
        print("Error creating indices or inserting initial document:", e)
        return False


def db_insert_if_new_url(
        url='',
        isopendir=None,
        visited=None,
        source='',
        content_type='',
        words='',
        min_webcontent='',
        raw_webcontent='',
        isnsfw='',
        resolution='',
        parent_host='',
        email=None,
        db=None,
        debug=False,
        fast_crawled=None):
    """
    Inserts a new URL document into the Elasticsearch database if it doesn't already exist.
    If the document exists, updates selective fields based on the current data.

    This function handles document deduplication by hashing the URL and uses
    Elasticsearch's `scripted_upsert` mechanism to insert or update the document atomically.
    It also adds metadata such as host levels, directory levels, query variables,
    and file extensions for better query and filtering support.

    Args:
        url (str): The target URL to insert or update in the database.
        isopendir (bool, optional): Indicates if the URL is an open directory.
        visited (bool, optional): Flag indicating if the URL has been visited.
        source (str, optional): Source of the URL (e.g., parent script or referring domain).
        content_type (str, optional): The content type of the page (e.g., 'text/html').
        words (str, optional): Extracted text content or word tokens from the page.
        min_webcontent (str, optional): A minimal filtered version of the web content.
        raw_webcontent (str, optional): The raw unprocessed HTML or page source.
        isnsfw (float or str, optional): NSFW confidence score or label (0–1).
        resolution (str or int, optional): Resolution value or score of the content.
        parent_host (str, optional): Parent host from which the URL was discovered.
        email (str, optional): Email address found on the page (if any).
        db (object): Database object with a `.con.update()` method (Elasticsearch wrapper).
        debug (bool): Enables verbose debug logging and value comparisons.
        fast_crawled (bool, optional): Whether this URL was fast-crawled (vs. full crawl).

    Returns:
        bool: True if insert/update was successful, False if an error occurred.

    Notes:
        - This function uses `hash_url(url)` to generate a unique document ID.
        - If the URL already exists, only fields with changed values are updated.
        - Emails are appended to the `emails` array only if they are new.
        - Host and directory levels are padded to fixed lengths for better filtering.
        - Uses retry logic on version conflict errors (up to 2 attempts).
    """
    host = urlsplit(url)[1]
    url = remove_jsessionid_with_semicolon(url)
    url = sanitize_url(url)
    parsed = urlsplit(url)
    query = parsed.query
    has_query = bool(query)
    query_dict = parse_qs(query)
    query_variables = list(set(query_dict.keys()))
    query_values = list(
            set(v for values in query_dict.values() for v in values)
            )
    now_iso = datetime.now(timezone.utc).isoformat()
    doc_id = hash_url(url)

    try:
        existing_doc = None
        if debug:
            try:
                existing_doc = db.con.get(
                        index=URLS_INDEX,
                        id=doc_id
                    )["_source"]
            except Exception:
                print(f"[DEBUG] Unable to get doc -{url}-: {get_err}")

        # Insert-only fields
        insert_only_fields = {
            "url": url,
            "host": host
        }

        if email:
            if isinstance(email, str):
                insert_only_fields["emails"] = [email]
            else:
                print(f"[Warning] Skipping non-string email: {email}")

        if existing_doc is None:
            insert_only_fields["random_bucket"] = random.randint(
                    0, ELASTICSEARCH_RANDOM_BUCKETS - 1)

            if source:
                insert_only_fields["source"] = source
            if parent_host:
                insert_only_fields["parent_host"] = parent_host

            # Safely extract host and directory levels
            host_parts = get_host_levels(host).get("host_levels", [])
            if len(host_parts) < MAX_HOST_LEVELS:
                host_parts = [''] * (
                        MAX_HOST_LEVELS - len(host_parts)) + host_parts

            dir_parts = get_directory_levels(
                    urlsplit(url).path).get("directory_levels", [])
            if len(dir_parts) < MAX_DIR_LEVELS:
                dir_parts = [''] * (
                        MAX_DIR_LEVELS - len(dir_parts)) + dir_parts

            # Add levels to insert_only_fields
            insert_only_fields["host_levels"] = host_parts
            insert_only_fields["directory_levels"] = dir_parts

            insert_only_fields["has_query"] = has_query
            if query_variables:
                insert_only_fields["query_variables"] = query_variables
            if query_values:
                insert_only_fields["query_values"] = query_values

            # Extract file extension if present
            path = unquote(urlsplit(url).path)
            _, file_extension = os.path.splitext(path)
            if file_extension:
                file_extension = file_extension.lower().lstrip('.')
            else:
                file_extension = ''

            if file_extension:
                insert_only_fields['file_extension'] = file_extension

            for i, part in enumerate(reversed(host_parts[-MAX_HOST_LEVELS:])):
                insert_only_fields[f"host_level_{i+1}"] = part

            for i, part in enumerate(dir_parts[:MAX_DIR_LEVELS]):
                insert_only_fields[f"directory_level_{i+1}"] = part

        # Fields that may be updated
        doc = {}
        if content_type:
            doc["content_type"] = content_type
        if fast_crawled is not None:
            doc["fast_crawled"] = bool(fast_crawled)
        if words:
            doc["words"] = words
        if min_webcontent:
            doc["min_webcontent"] = min_webcontent
        if raw_webcontent:
            doc["raw_webcontent"] = raw_webcontent
        if isopendir is not None:
            doc["isopendir"] = bool(isopendir)
        if isnsfw:
            doc["isnsfw"] = float(isnsfw)
        if resolution:
            resolution_str = str(resolution)
            if resolution_str.isdigit():
                doc["resolution"] = int(resolution_str)
            else:
                doc["resolution"] = 0
        if visited is not None:
            doc["visited"] = bool(visited)
        elif "visited" not in insert_only_fields:
            insert_only_fields["visited"] = False

        # Debug: show diff
        if debug:
            if existing_doc:
                for key, new_value in {**insert_only_fields, **doc}.items():
                    if key in ("random_bucket", "source", "parent_host"):
                        continue
                    old_value = existing_doc.get(key, None)
                    if key != "visited" and old_value != new_value:
                        print(f"[DEBUG] INSERT - Comparing update: {url}")
                        print(f"  {key}: '{old_value}' ➡ '{new_value}'")
            else:
                print(f"[DEBUG] INSERT - New document for URL: {url}")

            print(f"[DEBUG] Host levels for {url}: {host_parts}")
            print(f"[DEBUG] Directory levels for {url}: {dir_parts}")

        # Build update script
        script_lines = ["boolean has_updated = false;"]

        if isinstance(email, str):
            script_lines.append("""
                if (!ctx._source.containsKey('emails')) {
                    ctx._source.emails = [params.email];
                    has_updated = true;
                } else if (!ctx._source.emails.contains(params.email)) {
                    ctx._source.emails.add(params.email);
                    has_updated = true;
                }
            """)
            doc["email"] = email

        for key in doc:

            if key == "visited":
                script_lines.append(
                    """
                    if (!ctx._source.containsKey('visited') ||
                        ctx._source.visited == false) {
                        ctx._source.visited = params.visited;
                        has_updated = true;
                    }
                    """
                )

            else:
                script_lines.append(
                    f"""
                    if (params.containsKey('{key}')) {{
                        def old_val = ctx._source.containsKey('{key}')
                                      ? ctx._source['{key}']
                                      : null;
                        if (old_val != params['{key}']) {{
                            ctx._source['{key}'] = params['{key}'];
                            has_updated = true;
                        }}
                    }}
                    """
                )
        script_lines.append(
            "if (has_updated) { "
            "ctx._source.updated_at = params.updated_at; "
            "}"
        )
        script = "\n".join(script_lines)

        # Merge doc fields safely
        try:
            upsert_doc = {**insert_only_fields, **doc}
        except Exception as merge_err:
            print("[DEBUG] Error merging insert_only_fields and doc")
            print("  insert_only_fields:", insert_only_fields)
            print("  doc:", doc)
            raise merge_err

        upsert_doc["created_at"] = now_iso
        upsert_doc["updated_at"] = now_iso
        doc["updated_at"] = now_iso

        for attempt in range(2):  # Try up to 2 times
            try:
                db.con.update(
                    index=URLS_INDEX,
                    id=doc_id,
                    body={
                        "scripted_upsert": True,
                        "script": {
                            "source": script,
                            "lang": "painless",
                            "params": doc
                        },
                        "upsert": upsert_doc
                    }
                )
                return True  # Success on first or second attempt
            except ConflictError as ce:
                if attempt == 0:
                    if debug:
                        print(
                            "[RETRY] Version conflict on first attempt "
                            f"for URL: {url}"
                        )
                    time.sleep(0.05)  # Slight pause before retry
                else:
                    print(
                        "[Elasticsearch] Final ConflictError on retry for "
                        f"URL '{url}': {ce}"
                    )
                    return False
            except Exception as e:
                print(
                    "[Elasticsearch] Error inserting URL "
                    f"'{url}': {type(e).__name__} - {e}"
                )
                return False

    except Exception as e:
        print(
            "[Elasticsearch] Error inserting URL "
            f"'{url}': {type(e).__name__} - {e}"
        )
        return False


def mark_url_as_fast_crawled(url, db):
    db_insert_if_new_url(
        url=url,
        source='fast_extension_crawler.no_match',
        fast_crawled=True,
        db=db,
        debug=False
    )
    """
    Marks a URL as having been fast-crawled using the extension-based crawler.

    This function updates the corresponding URL document in the database, setting
    the `fast_crawled` flag to True and tagging the source as
    'fast_extension_crawler.no_match'.

    Args:
        url (str): The URL to mark as fast-crawled.
        db (object): The database connection object used to perform the update.

    Returns:
        None

    Notes:
        - This function uses `db_insert_if_new_url()` internally to perform an upsert.
        - If the URL does not already exist in the database, it will be created.
        - This is typically used for URLs that were scanned but didn’t match
          any criteria requiring deeper analysis.
    """


def get_host_levels(hostname):
    """
    Extracts hierarchical host levels from a hostname, excluding any port number.

    This function splits the given hostname into its individual levels (e.g.,
    subdomain, domain, TLD), ignoring any port suffix. It returns both the list
    of parts and a dictionary mapping each part to a named key (e.g., 'host_level_1').

    Args:
        hostname (str): The hostname to process, potentially including a port.

    Returns:
        dict: A dictionary with:
            - 'host_levels' (list[str]): List of host parts in left-to-right order.
            - 'host_level_map' (dict[str, str]): Mapping of each level to a key like 'host_level_1', 'host_level_2', etc.

    Example:
        get_host_levels("sub.example.co.uk:443")
        {
            "host_levels": ["sub", "example", "co", "uk"],
            "host_level_map": {
                "host_level_1": "sub",
                "host_level_2": "example",
                "host_level_3": "co",
                "host_level_4": "uk"
            }
        }
    """
    hostname = hostname.split(':')[0]  # Remove port if present
    parts = hostname.split('.')
    parts_reversed = list(parts)
    return {
        "host_levels": parts_reversed,
        "host_level_map": {
            f"host_level_{i+1}": level
            for i, level in enumerate(parts_reversed)
        }
    }


def get_directory_levels(url_path):
    """
    Extracts and maps directory levels from a given URL path.

    This function splits the path portion of a URL into individual directory levels.
    It ensures the result is always of length `MAX_DIR_LEVELS`, padding with empty
    strings if necessary. It also returns a dictionary that maps each level to a
    labeled key such as 'directory_level_1', 'directory_level_2', etc.

    Args:
        url_path (str): The path part of a URL (e.g., "/a/b/c/").

    Returns:
        dict: A dictionary with:
            - 'directory_levels' (list[str]): List of directory segments.
            - 'directory_level_map' (dict[str, str]): Mapping from labels to segments.

    Example:
        get_directory_levels("/products/electronics/phones/")
        {
            "directory_levels": ["products", "electronics", "phones", "", "", ...],
            "directory_level_map": {
                "directory_level_1": "products",
                "directory_level_2": "electronics",
                "directory_level_3": "phones",
                ...
            }
        }
    """
    # Split the URL path into parts and remove empty strings
    levels = [p for p in url_path.strip("/").split("/") if p]

    # Ensure the levels list is padded to MAX_DIR_LEVELS
    if len(levels) < MAX_DIR_LEVELS:
        levels = levels + [''] * (MAX_DIR_LEVELS - len(levels))  # Add empty levels at the end

    # Map the levels to their directory level numbers
    directory_level_map = {f"directory_level_{i+1}": levels[i] for i in range(len(levels))}

    return {
        "directory_levels": levels,
        "directory_level_map": directory_level_map
    }


# List of regex patterns used to match various content types that are considered HTML.
# This helps normalize and detect HTML-like responses across different servers and formats.
# Covers standard, non-standard, and vendor-specific content types.
content_type_html_regex = [
        r"^text/html$",
        r"^application/html$",
        r"^text/html,text/html",
        r"^text/fragment\+html$",
        r"^text/html, charset=.*",
        r"^text/x-html-fragment$",
        r"^application/xhtml\+xml$",
        r"^text/html,charset=UTF-8$",
        r"^text/vnd\.reddit\.partial\+html$",
    ]

# Regex patterns to match MIDI audio content types in HTTP headers
# Matches standard MIDI (audio/midi) and SP-MIDI (audio/sp-midi) formats
content_type_midi_regex = [
        r"^audio/midi$",
        r"^audio/sp-midi$",
    ]

# Regex patterns to match various audio content types in HTTP headers
# Covers standard audio formats (MP3, WAV, FLAC, OGG, etc.), streaming formats,
# proprietary formats (WMA, RealAudio), playlist formats (M3U, PLS), and
# generic binary types that may contain audio content
content_type_audio_regex = [
        r"^audio/ogg$",
        r"^audio/mp3$",
        r"^audio/mp4$",
        r"^audio/wav$",
        r"^audio/aac$",
        r"^audio/m4a$",
        r"^audio/s3m$",
        r"^audio/wave$",
        r"^audio/MP2T$",
        r"^audio/webm$",
        r"^audio/flac$",
        r"^audio/mpeg$",
        r"^audio/opus$",
        r"^audio/x-m4a$",
        r"^audio/x-m4p$",
        r"^audio/x-rpm$",
        r"^audio/x-s3m$",
        r"^audio/x-wav$",
        r"^audio/x-aiff$",
        r"^audio/x-flac$",
        r"^audio/unknown$",
        r"^audio/mpegurl$",
        r"^audio/x-scpls$",
        r"^audio/x-ms-wma$",
        r"^audio/prs\.sid$",
        r"^application/mp3$",
        r"^audio/x-mpegurl$",
        r"^application/mp4$",
        r"^audio/x-oggvorbis$",
        r"^audio/x-pn-realaudio$",
        r"^application/octetstream$",
        r"^application/octet-stream$",
        r"^application/x-octet-stream$",
        r"^audio/x-pn-realaudio-plugin$",
        r"^application/vnd\.rn-realmedia$",
    ]

# Regex patterns to match compressed file content types in HTTP headers
# Covers common archive and compression formats including ZIP, RAR, TAR, GZIP,
# BZIP2, XZ, and their various MIME type representations (standard and non-standard)
content_type_compressed_regex = [
        r"^multipart/x-zip$",
        r"^application/zip$",
        r"^application/rar$",
        r"^application/gzip$",
        r"^application/x-bzip$",
        r"^application/x-xz$",
        r"^application/\.rar$",
        r"^application/\.zip$",
        r"^application/x-zip$",
        r"^application/x-rar$",
        r"^application/x-tar$",
        r"^application/x-gzip$",
        r"^application/x-bzip2$",
        r"^application/vnd\.rar$",
        r"^application/x-tar-gz$",
        r"^application/vnd\.rar$",
        r"^application/x-compress$",
        r"^application/octetstream$",
        r"^application/octet-stream$",
        r"^application/x-octet-stream$",
        r"^application/x-7z-compressed$",
        r"^application/x-rar-compressed$",
        r"^application/x-zip-compressed$",
        r"^application/x-gtar-compressed$",
        r"^application/vnd\.ms-cab-compressed$",
        r"^application/x-zip-compressedcontent-length:",
        r"^application/vnd\.adobe\.air-application-installer-package\+zip$",
    ]

# Regex patterns to match PDF content types in HTTP headers
# Covers standard PDF MIME type (application/pdf) and various non-standard
# representations including Adobe-specific, x-prefixed variants, and malformed
# headers where PDF type may be concatenated with other header fields
content_type_pdf_regex = [
        r"^adobe/pdf$",
        r"^application/pdf$",
        r"^application/\.pdf$",
        r"^application/x-pdf$",
        r"^application/pdfcontent-length:",
    ]

# Regex patterns to match various image content types in HTTP headers
# Covers standard image formats (PNG, JPEG, GIF, WebP, etc.), modern formats
# (AVIF, HEIC), vector graphics (SVG), specialized formats (FITS, DWG), and
# malformed/non-standard MIME types including bare format names, null values,
# and data URLs that the crawler might encounter
content_type_image_regex = [
        r"^png$",
        r"^webp$",
        r"^jpeg$",
        r"^webpx$",
        r"^.jpeg$",
        r"^image/$",
        r"^image$",
        r"^img/jpeg$",
        r"^image/\*$",
        r"^image/any$",
        r"^image/bmp$",
        r"^image/gif$",
        r"^image/ico$",
        r"^image/jp2$",
        r"^image/jpg$",
        r"^image/pbf$",
        r"^image/png$",
        r"^image/svg$",
        r"^(null)/ico$",
        r"^image/heic$",
        r"^image/fits$",
        r"^image/apng$",
        r"^image/avif$",
        r"^image/jpeg$",
        r"^image/tiff$",
        r"^image/webp$",
        r"^image/pjpeg$",
        r"^image/x-png$",
        r"^image/x-eps$",
        r"^\(null\)/ico$",
        r"^image/dicomp$",
        r"^image/x-icon$",
        r"^image/\{png\}$",
        r"^data:image/png$",
        r"^image/vnd\.dwg$",
        r"^image/svg\+xml$",
        r"^image/x-ms-bmp$",
        r"^image/vnd\.djvu$",
        r"^image/x-xbitmap$",
        r"^image/x-photoshop$",
        r"^image/x-coreldraw$",
        r"^image/x-cmu-raster$",
        r"^image/vnd\.wap\.wbmp$",
        r"^image/x\.fb\.keyframes$",
        r"^image/vnd\.microsoft\.icon$",
        r"^image/vnd\.adobe\.photoshop$",
        r"^application/jpg$",
    ]

# Regex patterns to match database file content types in HTTP headers
# Covers SQL files and Microsoft Access database formats including
# standard and x-prefixed MIME type variations
content_type_database_regex = [
        r"^application/sql$",
        r"^application/msaccess$",
        r"^application/x-msaccess$",
        ]

# Regex patterns to match office document content types in HTTP headers
# Covers Microsoft Office formats (Word, Excel, PowerPoint), OpenDocument formats,
# legacy and modern Office versions, macro-enabled documents, templates, and
# various MIME type representations including shortened and fully-qualified names
content_type_doc_regex = [
        r"^application/doc$",
        r"^application/xls$",
        r"^application/xlsx$",
        r"^application/docx$",
        r"^application/msword$",
        r"^application/msexcel$",
        r"^application/ms-excel$",
        r"^application/x-msexcel$",
        r"^application/vnd\.visio$",
        r"^application/vnd\.ms-excel$",
        r"^application/vnd\.ms-word\.document\.12$",
        r"^application/vnd\.ms-excel\.openxmlformat$",
        r"^application/vnd\.oasis\.opendocument\.text$",
        r"^application/vnd\.ms-excel\.sheet\.macroenabled\.12$",
        r"^application/vnd\.ms-powerpoint\.slideshow\.macroEnabled\.12$",
        r"^application/vnd\.openxmlformats-officedocument\.spreadsheetml\.sheet$",
        r"^application/vnd\.openxmlformats-officedocument\.presentationml\.slideshow",
        r"^application/vnd\.openxmlformats-officedocument\.wordprocessingml\.document$",
        r"^application/vnd\.openxmlformats-officedocument\.wordprocessingml\.template$",
        r"^application/vnd\.openxmlformats-officedocument\.presentationml\.presentation$",
        ]

# Regex patterns to match BitTorrent file content types in HTTP headers
# Covers the standard BitTorrent MIME type and generic binary/octet-stream
# types that may be used for torrent files, including various spellings
# and representations of octet-stream
content_type_torrent_regex = [
        r"^application/x-bittorrent$",
        r"^application/octetstream$",
        r"^application/octet-stream$",
        r"^application/x-octet-stream$",
        ]

# Regex patterns to match font file content types in HTTP headers
# Covers modern web fonts (WOFF, WOFF2), traditional fonts (TTF, OTF),
# legacy formats (EOT), and various non-standard MIME type representations
# including x-prefixed variants and misclassified types (e.g., image/otf)
content_type_font_regex = [
        r"^woff$",
        r"^woff2$",
        r"^font/eot$",
        r"^font/ttf$",
        r"^font/otf$",
        r"^font/sfnt$",
        r"^image/otf$",
        r"^font/woff$",
        r"^x-font/ttf$",
        r"^font/woff2$",
        r"^fonts/woff2$",
        r"^font/x-woff$",
        r"^x-font/woff$",
        r"^font/x-woff2$",
        r"^font/truetype$",
        r"^font/opentype$",
        r"^font/font-woff$",
        r"^\(null\)/woff2$",
        r"^font/font-woff2$",
        r"^application/ttf$",
        r"^application/font$",
        r"^application/woff$",
        r"^application/x-woff$",
        r"^application/x-woff2$",
        r"^application/font-otf$",
        r"^application/font-ttf$",
        r"^application/font-sfnt$",
        r"^application/font-woff$",
        r"^application/x-font-ttf$",
        r"^application/x-font-otf$",
        r"^application/font/woff2$",
        r"^application/font-woff2$",
        r"^application/x-font-woff$",
        r"^application/x-font-woff2$",
        r"^application/x-font-truetype$",
        r"^application/x-font-opentype$",
        r"^value=application/x-font-woff2$",
        r"^application/font-woff2,font/woff2$",
        r"^font/woff2\|application/octet-stream\|font/x-woff2$",
        ]

# Regex patterns to match video file content types in HTTP headers
# Covers modern video formats (MP4, WebM, OGG), legacy formats (AVI, WMV),
# mobile formats (3GPP), streaming formats (M2TS, F4V), and non-standard
# MIME types including application/ prefixed variants for video content
content_type_video_regex = [
        r"^video/mp4$",
        r"^video/ogg$",
        r"^video/f4v$",
        r"^video/3gpp$",
        r"^video/m2ts$",
        r"^video/webm$",
        r"^video/MP2T$",
        r"^video/mpeg$",
        r"^video/x-m4v$",
        r"^video/x-flv$",
        r"^video/x-ms-wm$",
        r"^video/x-ms-wmv$",
        r"^video/x-ms-asf$",
        r"^application/ogg$",
        r"^application/wmv$",
        r"^application/avi$",
        r"^application/mp4$",
        r"^video/x-msvideo$",
        r"^video/quicktime$",
        r"^application/mp4$",
        r"^video/x-matroska$",
        r"^video/iso.segment$",
        r"^application/x-mpegurl$",
        r"^video/vnd\.objectvideo$",
        r"^application/octetstream$",
        r"^application/vnd\.ms-asf$",
        r"^application/octet-stream$",
        r"^video/vnd\.dlna\.mpeg-tts$",
        r"^application/x-octet-stream$",
        r"^application/x-shockwave-flash$",
        r"^application/vnd\.apple\.mpegurl$",
        r"^application/vnd\.adobe\.flash\.movie$",
        r"^application/mp4,audio/mp4,video/mp4,video/vnd\.objectvideo$",
        ]

# Regex patterns to match plain text and text-based file content types in HTTP headers
# Covers standard text formats (plain, CSV, XML, JSON), programming languages
# (JavaScript, Go, Perl, C), markup formats (RTF, YAML), subtitle formats (SRT, VTT),
# system files (shell scripts, logs, diffs), and various non-standard MIME type
# representations that should be processed as readable text content
content_type_plain_text_regex = [
        r"^\.js$",
        r"^text/\*$",
        r"^text/js$",
        r"^text/xml$",
        r"^text/srt$",
        r"^text/rtf$",
        r"^text/csv$",
        r"^text/vtt$",
        r"^app/json$",
        r"^text/x-c$",
        r"^text/x-sh$",
        r"^text/json$",
        r"^text/yaml$",
        r"^text/x-go$",
        r"^text/x-js$",
        r"^plain/text$",
        r"^text/x-csh$",
        r"^text/x-log$",
        r"^text/vcard$",
        r"^text/x-tex$",
        r"^text/plain$",
        r"^text/x-wiki$",
        r"^text/x-diff$",
        r"^text/x-perl$",
        r"^text/x-chdr$",
        r"^text/x-json$",
        r"^text/x-csrc$",
        r"^text/turtle$",
        r"^text/webloc$",
        r"^text/x-vcard$",
        r"^text/calendar$",
        r"^text/x-ndjson$",
        r"^text/x-bibtex$",
        r"^text/uri-list$",
        r"^text/markdown$",
        r"^text/x-python$",
        r"^text/directory$",
        r"^text/x-amzn-ion$",
        r"^text/javsacript$",
        r"^text/ecmascript$",
        r"^text/x-vcalendar$",
        r"^text/x-component$",
        r"^application/text$",
        r"^text/x-html-parts$",
        r"^application/jsonp$",
        r"^text/x-javascript$",
        r"^text/event-stream$",
        r"^text/vnd\.graphviz$",
        r"^application/ld\+json$",
        r"^application/ion\+json$",
        r"^application/hal\+json$",
        r"^text/txtcharset=utf-8$",
        r"^applicaiton/jasvascript$",
        r"^application/json,charset=",
        r"^application/stream\+json$",
        r"^application/problem\+json$",
        r"^text/0\.4/hammer\.min\.js$",
        r"^application/expanded\+json$",
        r"^text/x-handlebars-template$",
        r"^application/vnd\.api\+json$",
        r"^application/x-thrift\+json$",
        r"^application/json\+protobuf$",
        r"^application/manifest\+json$",
        r"^application/importmap\+json$",
        r"^application/x-amz-json-1\.1$",
        r"^text/vnd\.turbo-stream\.html$",
        r"^text/vnd\.trolltech\.linguist$",
        r"^application/jsoncharset=UTF-8$",
        r"^text/x-comma-separated-values$",
        r"^application/json,application/json$",
    ]

# Regex patterns to match URLs that should be ignored or handled as no-ops
# Covers fragment identifiers (#), empty URLs, various protocol schemes that
# are not crawlable web content (social media, messaging, file system, version
# control, streaming, news feeds, etc.), and application-specific schemes that
# don't represent standard web resources accessible via HTTP/HTTPS
url_all_others_regex = [
        r"^#",
        r"^$",
        r"^\$",
        r"^tg:",
        r"^fb:",
        r"^app:",
        r"^apt:",
        r"^geo:",
        r"^sms:",
        r"^ssh:",
        r"^fax:",
        r"^fon:",
        r"^git:",
        r"^svn:",
        r"^wss:",
        r"^mms:",
        r"^aim:",
        r"^rtsp:",
        r"^file:",
        r"^feed:",
        r"^itpc:",
        r"^news:",
        r"^atom:",
        r"^nntp:",
        r"^sftp:",
        r"^data:",
        r"^apps:",
        r"^xmpp:",
        r"^void:",
        r"^waze:",
        r"^itms:",
        r"^viber:",
        r"^steam:",
        r"^ircs*:",
        r"^skype:",
        r"^ymsgr:",
        r"^event:",
        r"^about:",
        r"^movie:",
        r"^rsync:",
        r"^popup:",
        r"^itmss:",
        r"^chrome:",
        r"^telnet:",
        r"^webcal:",
        r"^magnet:",
        r"^vscode:",
        r"^mumble:",
        r"^unsafe:",
        r"^podcast:",
        r"^spotify:",
        r"^bitcoin:",
        r"^threema:",
        r"^\.onion$",
        r"^\(none\)$",
        r"^ethereum:",
        r"^litecoin:",
        r"^whatsapp:",
        r"^x-webdoc:",
        r"^appstream:",
        r"^worldwind:",
        r"^itms-apps:",
        r"^itms-beta:",
        r"^applenewss:",
        r"^santanderpf:",
        r"^bitcoincash:",
        r"^android-app:",
        r"^ms-settings:",
        r"^applewebdata:",
        r"^fb-messenger:",
        r"^moz-extension:",
        r"^x-help-action:",
        r"^microsoft-edge:",
        r"^digitalassistant:",
        r"^chrome-extension:",
        r"^ms-windows-store:",
        r"^(tel:|tellto:|te:|callto:|TT:|tell:|telto:|phone:|calto:|call:|telnr:|tek:|sip:|to:|SAC:|facetime-audio:|telefone:|telegram:|tel\+:|tal:|tele:|tels:|cal:|tel\.:)",
        r"^(javascript:|javacscript:|javacript:|javascripy:|javscript:|javascript\.|javascirpt:|javascript;|javascriot:|javascritp:|havascript:|javescript:|javascrip:|javascrpit:|js:|javascripr:|javastript:|javascipt:|javsacript:|javasript:|javascrit:|javascriptt:|ja vascript:|javascrtipt:|jasvascript:|javascropt:|jvascript:|javasctipt:|avascript:|javacsript:)",
    ]

# Regex patterns to match miscellaneous content types that don't fit other categories
# Covers empty/null values, generic types (binary, unknown), malformed MIME types,
# CSS/JavaScript variants, 3D model formats, programming languages (MATLAB, Haskell),
# redirects, multipart content, and various non-standard or incorrectly formatted
# content type headers that require catch-all handling
content_type_all_others_regex = [
        r"^$",
        r"^-$",
        r"^js$",
        r"^\*$",
        r"^None$",
        r"^json$",
        r"^null$",
        r"^file$",
        r"^\*/\*$",
        r"^binary$",
        r"^unknown$",
        r"^text/css$",
        r"^redirect$",
        r"^model/usd$",
        r"^model/stl$",
        r"^model/obj$",
        r"^model/step$",
        r"^test/plain$",
        r"^text/octet$",
        r"^text/x-scss$",
        r"^application$",
        r"^Content-Type$",
        r"^octet/stream$",
        r"^cms/redirect$",
        r"^message/news$",
        r"^text/x-matlab$",
        r"^inode/x-empty$",
        r"^text/x-invalid$",
        r"^application/js$",
        r"^application/\*$",
        r"^model/vnd\.mts$",
        r"^text/x-haskell$",
        r"^application/jsv$",
        r"^unknown/unknown$",
        r"^multipart/mixed$",
        r"^application/cgi$",
        r"^text/javascript$",
        r"^application/xml$",
        r"^application/x-j$",
        r"^application/jwt$",
        r"^application/rtf$",
        r"^application/csv$",
        r"^application/acad$",
        r"^application/x-po$",
        r"^application/mbox$",
        r"^application/epub$",
        r"^application/node$",
        r"^application/smil$",
        r"^application/wasm$",
        r"^application/x-js$",
        r"^application/mobi$",
        r"^application/save$",
        r"^application/null$",
        r"^application/zlib$",
        r"^application/json$",
        r"^application/x-sh$",
        r"^application/empty$",
        r"^application/x-cbr$",
        r"^text/plaincharset:",
        r"^chemical/x-cerius$",
        r"^application/x-rpm$",
        r"^application/x-twb$",
        r"^application/x-xcf$",
        r"^application/x-msi$",
        r"^application/x-xar$",
        r"^application/proto$",
        r"^model/gltf-binary$",
        r"^application/x-shar$",
        r"^application/x-ruby$",
        r"^application/x-frpc$",
        r"^application/x-tgif$",
        r"^application/x-perl$",
        r"^application/binary$",
        r"^application/json-p$",
        r"^application/turtle$",
        r"^application/x-doom$",
        r"^application/x-troff$",
        r"^text/remix-deferred$",
        r"^binary/octet-stream$",
        r"^application/express$",
        r"^multipart/form-data$",
        r"^application/x-trash$",
        r"^application/unknown$",
        r"^application/xml-dtd$",
        r"^application/x-empty$",
        r"^application/x-blorb$",
        r"^application/java-vm$",
        r"^application/rfc\+xml$",
        r"^application/x-netcdf$",
        r"^application/gml\+xml$",
        r"^chemical/x-molconn-Z$",
        r"^application/x-ndjson$",
        r"^application/x-nozomi$",
        r"^application/x-adrift$",
        r"^application/x-binary$",
        r"^application/rdf\+xml$",
        r"^application/hr\+json$",
        r"^application/download$",
        r"^application/rss\+xml$",
        r"^application/x-msword$",
        r"^application/pgp-keys$",
        r"^application/x-subrip$",
        r"^application/x-bibtex$",
        r"^application/pkix-crl$",
        r"^httpd/unix-directory$",
        r"^application/x-stuffit$",
        r"^application/calques3d$",
        r"^application/n-triples$",
        r"^application/vnd\.smaf$",
        r"^application/geo\+json$",
        r"^application/ttml\+xml$",
        r"^application/xslt\+xml$",
        r"^application/dash\+xml$",
        r"^application/x-dosexec$",
        r"^application/epub\+zip$",
        r"^application/atom\+xml$",
        r"^application/pkix-cert$",
        r"^application/smil\+xml$",
        r"^text/javascript=UTF-8$",
        r"^application/x-zmachine$",
        r"^application/typescript$",
        r"^application/feed\+json$",
        r"^application/x-director$",
        r"^application/postscript$",
        r"^application/x-rss\+xml$",
        r"^application/ecmascript$",
        r"^application/x-protobuf$",
        r"^application/pkcs7-mime$",
        r"^application/javascript$",
        r"^application/oct-stream$",
        r"^application/vnd\.ms-wpl$",
        r"^application/x-asciicast$",
        r"^applications/javascript$",
        r"^javascriptcharset=UTF-8$",
        r"^chemical/x-galactic-spc$",
        r"^application/vnd\.yt-ump$",
        r"^application/octetstream$",
        r"^application/x-xpinstall$",
        r"^application/x-httpd-php$",
        r"^application/x-directory$",
        r"^application/x-troff-man$",
        r"^application/mac-binhex40$",
        r"^application/schema\+json$",
        r"^application/encrypted-v2$",
        r"^application/java-archive$",
        r"^application/x-javascript$",
        r"^application/x-msdownload$",
        r"^application/octet-stream$",
        r"^application/vnd\.ms-word$",
        r"^application/v3\.24\+json$",
        r"^application/x-executable$",
        r"^application/marcxml\+xml$",
        r"^application/v3\.25\+json$",
        r"^javascript charset=UTF-8$",
        r"^application/linkset\+json$",
        r"^application/x-ipynb\+json$",
        r"^application/jwk-set\+json$",
        r"^multipart/x-mixed-replace$",
        r"^application/pgp-encrypted$",
        r"^application/x-base64-frpc$",
        r"^application/pgp-signature$",
        r"^application/x-ms-manifest$",
        r"^application/x-mobi8-ebook$",
        r"^application/grpc-web-text$",
        r"^application/activity\+json$",
        r"^application/force-download$",
        r"^application/vnd\.geo\+json$",
        r"^application/vnd\.visionary$",
        r"^application/x-java-archive$",
        r"^application/x-octet-stream$",
        r"^application/x-x509-ca-cert$",
        r"^x-application/octet-stream$",
        r"^application/x-endnote-refer$",
        r"^application/vnd\.olpc-sugar$",
        r"^text/x-unknown-content-type$",
        r"^application/grpc-web\+proto$",
        r"^application/x-amz-json-1\.0$",
        r"^application/x-msdos-program$",
        r"^application/x-iso9660-image$",
        r"^application/x-csp-hyperevent$",
        r"^application/vnd\.siren\+json$",
        r"^application/x-ms-application$",
        r"^application/vnd\.ms-opentype$",
        r"^application/x-debian-package$",
        r"^application/x-httpd-ea-php54$",
        r"^application/vnd\.ms-htmlhelp$",
        r"^application/x-shared-scripts$",
        r"^application/x-java-jnlp-file$",
        r"^application/x-httpd-ea-php71$",
        r"^application/rls-services\+xml$",
        r"^Content-Type:application/json$",
        r"^application/vnd\.ogc\.wms_xml$",
        r"^application/x-apple-diskimage$",
        r"^:application/application/json$",
        r"^application/vnd\.bestbuy\+json$",
        r"^application/x-chrome-extension$",
        r"^application/x-mobipocket-ebook$",
        r"^application/vnd\.1cbn\.v1+json$",
        r"^application/vnd\.ms-fontobject$",
        r"^application/privatetempstorage$",
        r"^application/vnd\.ms-powerpoint$",
        r"^application/vnd\.openxmlformats$",
        r"^application/apple\.vnd\.mpegurl$",
        r"^application/vnd\.ms-officetheme$",
        r"^application/vnd\.wv\.csp\+wbxml$",
        r"^application/x-ms-dos-executable$",
        r"^application/vnd\.1cbn\.v1\+json$",
        r"^application/vnd\.geogebra\.file$",
        r"^application/grpc-web-text\+proto$",
        r"^application/sparql-results\+json$",
        r"^application/vnd\.lotus-screencam$",
        r"^application/vnd\.imgur\.v1\+json$",
        r"^application/x-pkcs7-certificates$",
        r"^application/vnd\.adobe\.dex\+json$",
        r"^application/x-www-form-urlencoded$",
        r"^application/vnd\.google-earth\.kmz$",
        r"^application/vnd\.solid-v1\.0\+json$",
        r"^application/x-typekit-augmentation$",
        r"^application/x-unknown-content-type$",
        r"^application/graphql-response\+json$",
        r"^application/speculationrules\+json$",
        r"^application/vnd\.vimeo\.user\+json$",
        r"^application/octet-stream,text/html$",
        r"^application/vnd\.wg\.cds_api\+json$",
        r"^application/json-amazonui-streaming$",
        r"^application/vnd\.vimeo\.video\+json$",
        r"^application/x-research-info-systems$",
        r"^application/vnd\.mapbox-vector-tile$",
        r"^application/amazonui-streaming-json$",
        r"^application/vnd\.vimeo\.error\+json$",
        r"^application/json\+containerv1-server$",
        r"^application/vnd.groove-tool-template$",
        r"^application/vnd\.vimeo\.credit\+json$",
        r"^application/vnd\.cas\.services\+yaml$",
        r"^application/vnd.inveniordm\.v1\+json$",
        r"^application/x-redhat-package-manager$",
        r"^application/octet-streamCharset=UTF-8$",
        r"^application/vnd\.vimeo\.comment\+json$",
        r"^application/vnd\.vimeo\.location\+json$",
        r"^application/opensearchdescription\+xml$",
        r"^application/vnd\.google-earth\.kml\+xml$",
        r"^application/vnd\.com\.amazon\.api\+json$",
        r"^application/vnd\.treasuredata\.v1\+json$",
        r"^application/vnd\.mangahigh\.api-v1\+json$",
        r"^application/vnd\.maxmind\.com-city\+json$",
        r"^application/vnd\.initializr\.v2\.2\+json$",
        r"^application/vnd\.maxmind\.com-error\+json$",
        r"^application/vnd\.android\.package-archive$",
        r"^application/vnd\.radio-canada\.neuro\+json$",
        r"^application/vnd\.vimeo\.profilevideo\+json$",
        r"^application/vnd\.oracle\.adf\.version\+json$",
        r"^application/vnd\.maxmind\.com-country\+json$",
        r"^application/vnd\.treasuredata\.v1\.js\+json$",
        r"^application/vnd\.disney\.error\.v1\.0\+json$",
        r"^application/vnd\.vimeo\.currency\.json\+json$",
        r"^application/vnd\.maxmind\.com-insights\+json$",
        r"^application/vnd\.adobe\.error-response\+json$",
        r"^application/vnd\.vimeo\.profilesection\+json$",
        r"^application/vnd\.abc\.terminus\.content\+json$",
        r"^application/javascript,application/javascript$",
        r"^application/vnd\.vimeo\.video\.texttrack\+json$",
        r"^application/vnd\.contentful\.delivery\.v1\+json$",
        r"^application/javascript,application/x-javascript$",
        r"^application/vnd\.spring-boot\.actuator\.v3\+json$",
        r"^application/vnd\.vimeo\.marketplace\.skill\+json$",
        r"^application/vnd\.oasis\.opendocument\.spreadsheet$",
        r"^application/vnd\.disney\.field\.error\.v1\.0\+json$",
        r"^application/vnd\.google\.octet-stream-compressible$",
        r"^application/vnd\.oasis\.opendocument\.presentation$",
        r"^application/vnd.oasis.opendocument.formula-template$",
        r"^application/vnd\.openxmlformats-officedocument\.spre$",
        r"^application/vnd\.oracle\.adf\.resourcecollection\+json$",
        r"^application/vnd\.vmware\.horizon\.manager\.branding\+json$",
    ]

# Mapping of file extensions to their corresponding content-type regex groups.
# This is used during fast extension-based crawling to decide which handler should process a file
# based on its extension before fetching the actual content type.
#
# IMPORTANT: When adding a new extension and its corresponding content-type group here,
# make sure to also update the `needs_download` logic in the `fast_extension_crawler` function
# so the new type is either downloaded or skipped as expected.
#
# Additionally, ensure a corresponding handler function is decorated with
# @function_for_content_type(<your_new_regex>) and implemented properly
# to process and optionally store the file.
EXTENSION_MAP = {
        ".aac": content_type_audio_regex,
        ".aif": content_type_audio_regex,
        ".flac": content_type_audio_regex,
        ".m4a": content_type_audio_regex,
        ".mp3": content_type_audio_regex,
        ".ogg": content_type_audio_regex,
        ".rm": content_type_audio_regex,
        ".s3m": content_type_audio_regex,
        ".wav": content_type_audio_regex,
        ".Z": content_type_compressed_regex,
        ".lz": content_type_compressed_regex,
        ".7z": content_type_compressed_regex,
        ".gz": content_type_compressed_regex,
        ".zip": content_type_compressed_regex,
        ".bz2": content_type_compressed_regex,
        ".cab": content_type_compressed_regex,
        ".rar": content_type_compressed_regex,
        ".sql": content_type_database_regex,
        ".mdb": content_type_database_regex,
        ".doc": content_type_doc_regex,
        ".docx": content_type_doc_regex,
        ".vsd": content_type_doc_regex,
        ".xls": content_type_doc_regex,
        ".xlsx": content_type_doc_regex,
        ".ttf": content_type_font_regex,
        ".otf": content_type_font_regex,
        ".eot": content_type_font_regex,
        ".TTF": content_type_font_regex,
        ".woff": content_type_font_regex,
        ".woff2": content_type_font_regex,
        ".gif": content_type_image_regex,
        ".ico": content_type_image_regex,
        ".jp2": content_type_image_regex,
        ".jpg": content_type_image_regex,
        ".JPG": content_type_image_regex,
        ".pbf": content_type_image_regex,
        ".png": content_type_image_regex,
        ".PNG": content_type_image_regex,
        ".psd": content_type_image_regex,
        ".svg": content_type_image_regex,
        ".fits": content_type_image_regex,
        ".HEIC": content_type_image_regex,
        ".jpeg": content_type_image_regex,
        ".tiff": content_type_image_regex,
        ".mid": content_type_midi_regex,
        ".Mid": content_type_midi_regex,
        ".midi": content_type_midi_regex,
        ".pdf": content_type_pdf_regex,
        ".torrent": content_type_torrent_regex,
        ".wm": content_type_video_regex,
        ".mp4": content_type_video_regex,
        ".wmv": content_type_video_regex,
        ".3gp": content_type_video_regex,
        ".mkv": content_type_video_regex,
        ".swf": content_type_video_regex,
        ".asf": content_type_video_regex,
        ".m4s": content_type_video_regex,
        ".ogv": content_type_video_regex,
        ".mov": content_type_video_regex,
        ".MOV": content_type_video_regex,
        ".flv": content_type_video_regex,
        ".mpg": content_type_video_regex,
        ".mpeg": content_type_video_regex,
        ".webm": content_type_video_regex,
    }

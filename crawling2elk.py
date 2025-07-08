#!venv/bin/python3
import absl.logging
import argparse
import bs4.builder
import fcntl
import hashlib
import logging
import numpy as np
import os
import random
import re
import requests
import signal
import string
import subprocess
import time
import urllib3
import warnings
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import *
from datetime import datetime, timezone
from elasticsearch import helpers, ConflictError
from fake_useragent import UserAgent
from functions import *
from googlesearch import search
from io import BytesIO
from pathlib import PurePosixPath
from PIL import Image, UnidentifiedImageError
from seleniumwire import webdriver
from seleniumwire.utils import decode
from tornado import httpserver, ioloop, web
from urllib.parse import unquote, urljoin, urlparse, urlsplit
from urllib3.exceptions import InsecureRequestWarning


"""
Conditionally loads the OpenNSFW2 model for image classification.

This function checks whether NSFW content categorization is enabled via the
`CATEGORIZE_NSFW` flag. If enabled, it imports the `opennsfw2` module and
initializes the pre-trained NSFW classification model using `make_open_nsfw_model()`.
"""
if CATEGORIZE_NSFW:
    import opennsfw2 as n2
    model = n2.make_open_nsfw_model()

absl.logging.set_verbosity('error')
warnings.filterwarnings("ignore", category=InsecureRequestWarning)
warnings.filterwarnings(
        "ignore",
        category=Warning,
        message=".*verify_certs=False is insecure.*")
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url_functions = []
content_type_functions = []
lock_file = None  # Global reference to prevent garbage collection

# Used to generate wordlist
soup_tag_blocklist = [
    "[document]",
    "noscript",
    "header",
    "html",
    "meta",
    "head",
    "input",
    "script",
    "style",
]


def is_host_block_listed(url):
    """
    Check if a given URL matches any pattern in the host blocklist.

    This function iterates through a predefined list of regular expressions
    (`HOST_REGEX_BLOCK_LIST`) and checks if the given URL matches any of them.
    The match is case-insensitive and Unicode-aware.

    Args:
        url (str): The URL to check against the blocklist.

    Returns:
        bool: True if the URL matches any blocklist pattern, False otherwise.
    """
    for regex in HOST_REGEX_BLOCK_LIST:
        if re.search(regex, url, flags=re.I | re.U):
            return True
    return False


def is_url_block_listed(url):
    """
    Check if a given URL matches any pattern in the URL blocklist.

    This function scans the input URL against a predefined list of regular
    expressions (`URL_REGEX_BLOCK_LIST`) to determine if it should be blocked.
    The match is performed in a case-insensitive and Unicode-aware manner.

    Args:
        url (str): The full URL to check against the blocklist.

    Returns:
        bool: True if the URL matches any blocklist pattern, False otherwise.
    """
    for regex in URL_REGEX_BLOCK_LIST:
        if re.search(regex, url, flags=re.I | re.U):
            return True
    return False


def is_host_allow_listed(url):
    """
    Check if a URL's host matches any regular expression in the allowlist.

    This function iterates through the `HOST_REGEX_ALLOW_LIST`, which contains
    regular expression patterns representing hosts that are explicitly allowed.
    If the host part of the given URL matches any of the patterns, the function returns True.

    Args:
        url (str): The URL to evaluate.

    Returns:
        bool: True if the URL matches an allowlist pattern, False otherwise.
    """
    for regex in HOST_REGEX_ALLOW_LIST:
        if re.search(regex, url, flags=re.I | re.U):
            return True
    return False


def build_conditional_update_script(doc: dict) -> tuple[str, dict]:
    """
    Builds a dynamic Elasticsearch update script that only updates fields
    if their values have changed or meet specific conditions. This reduces
    unnecessary writes and keeps the `updated_at` timestamp accurate.

    Special logic is applied for:
    - `visited`: Only set it to True if it was previously null or False.
    - `updated_at`: This is updated only if any field has actually changed.

    Args:
        doc (dict): A dictionary representing the fields to update in the document.
                    Expected to include `updated_at` and may include `visited`.

    Returns:
        tuple[str, dict]:
            - A string representing the Elasticsearch painless script.
            - A dictionary of parameters to be passed with the script (`params`).

    Example:
        doc = {
            "visited": True,
            "content_type": "text/html",
            "updated_at": "2025-06-03T13:00:00Z"
        }

        script, params = build_conditional_update_script(doc)
        # Use `script` and `params` with Elasticsearch update API
    """
    script_lines = []
    params = {}

    for key, value in doc.items():
        params[key] = value

        if key == "visited":
            # Only set 'visited' to True if it is not already True
            script_lines.append(
                "if (ctx._source.visited == null || "
                "ctx._source.visited == false) {\n"
                "    ctx._source.visited = params.visited;\n"
                "}"
            )
        elif key != "updated_at":
            # Conditionally update other fields only if they changed
            script_lines.append(
                f"if (ctx._source['{key}'] != params['{key}']) {{\n"
                f"    ctx._source['{key}'] = params['{key}'];\n"
                f"}}"
            )

    # Update `updated_at` only if anything in the source has changed
    script_lines.append(
        "if (ctx._source != params.existing_source_snapshot) {\n"
        "    ctx._source.updated_at = params.updated_at;\n"
        "}"
    )

    return "\n".join(script_lines), params


def get_words(text: bytes | str) -> list[str]:
    """
    Extracts a list of top words from a given text input (bytes or string).

    This function ensures the text is decoded to UTF-8 (if it's in bytes), handles
    decoding errors gracefully, and passes the result to a word-extraction utility.

    Args:
        text (bytes | str): The input text to process. Can be raw bytes or a decoded string.

    Returns:
        list[str]: A list of extracted top words from the input text.
                   Returns an empty list if input is empty or decoding fails.

    Notes:
        - If `text` is bytes, it's decoded using UTF-8 with replacement for errors.
        - The actual word extraction logic is handled by `extract_top_words_from_text()`.
    """
    if not text:
        return []
    if isinstance(text, bytes):
        try:
            text = text.decode('utf-8', errors='replace')
        except Exception:
            return []
    return extract_top_words_from_text(text)


def get_words_from_soup(soup) -> list[str]:
    """
    Extracts top words from the visible text content of a BeautifulSoup HTML document.

    This function gathers all text strings from the soup object, excluding those
    inside blacklisted tags (defined in `soup_tag_blocklist`), and then extracts
    the most relevant words using `extract_top_words_from_text()`.

    Args:
        soup (bs4.BeautifulSoup): A BeautifulSoup object representing parsed HTML content.

    Returns:
        list[str]: A list of significant words extracted from the visible text content.

    Notes:
        - Tags in `soup_tag_blocklist` (e.g., <script>, <style>, etc.) are ignored.
        - Text is combined into a single string before keyword extraction.
    """
    text_parts = [
        t for t in soup.find_all(string=True)
        if t.parent.name not in soup_tag_blocklist
    ]
    combined_text = " ".join(text_parts)
    return extract_top_words_from_text(combined_text)


def get_min_webcontent(soup):
    """
    Extracts minimal visible textual content from a BeautifulSoup object.

    This function collects all text nodes from the HTML, excluding those that are
    children of tags in a predefined blocklist (e.g., <script>, <style>). It returns
    a single string with the combined visible text content.

    Args:
        soup (bs4.BeautifulSoup): A parsed HTML document.

    Returns:
        str: A space-separated string of visible text extracted from the HTML,
             excluding content in ignored tags.

    Example:
         get_min_webcontent(soup)
        'Welcome to my website This is the homepage ...'
    """
    text_parts = [
        t for t in soup.find_all(string=True)
        if t.parent.name not in soup_tag_blocklist
    ]
    combined_text = " ".join(text_parts)
    return combined_text


def extract_top_words_from_text(text: str) -> list[str]:
    """
    Processes a text string and returns the most frequent words based on configuration.

    This function cleans and normalizes the input text by optionally removing special
    characters and converting it to lowercase. It then filters words by length, counts
    their frequencies, and returns the top N most common words.

    Behavior is controlled by the following global settings:
        - WORDS_REMOVE_SPECIAL_CHARS (bool): If True, removes punctuation/special chars.
        - WORDS_TO_LOWER (bool): If True, converts all words to lowercase.
        - WORDS_MIN_LEN (int): Minimum word length to consider.
        - WORDS_MAX_LEN (int): Maximum word length to consider.
        - WORDS_MAX_WORDS (int): Number of top frequent words to return.

    Args:
        text (str): The input text to process.

    Returns:
        list[str]: A list of the most frequent words, ordered by frequency.

    Example:
        extract_top_words_from_text("Hello world! Hello again.")
        ['hello', 'world', 'again']
    """
    if WORDS_REMOVE_SPECIAL_CHARS:
        text = re.sub(r'[^\w\s]', ' ', text, flags=re.UNICODE)
    if WORDS_TO_LOWER:
        text = text.lower()

    words = [word for word in text.split() if
             WORDS_MIN_LEN < len(word) <= WORDS_MAX_LEN]
    most_common = Counter(words).most_common(WORDS_MAX_WORDS)
    return [word for word, _ in most_common]


def is_open_directory(content, content_url):
    """
    Determines whether the given HTML content represents an open directory listing.

    The function inspects the provided HTML content for patterns commonly found in open
    directory pages generated by various web servers and directory listing tools
    (e.g., Apache, Nginx, IIS, Lighttpd, h5ai, DUFS, Caddy, AList, etc.).

    It uses a list of known regex patterns that match common directory listing UIs,
    titles, and structural elements to make this determination. If any of the patterns
    are found in the content, the function assumes it's an open directory.

    Args:
        content (str): The HTML content of the page to analyze.
        content_url (str): The full URL of the page (used to extract host info for
                           dynamic pattern matching).

    Returns:
        bool: True if the content appears to be an open directory listing, False otherwise.

    Side Effects:
        Prints a debug message to stdout if a matching pattern is found, including the
        matched URL and pattern.

    Example:
        html = "<title>Index of /files</title><a href='file1.txt'>file1.txt</a>"
        is_open_directory(html, "http://example.com/files/")
        True
    """
    host = urlsplit(content_url)[1]
    hostnp = host.split(':')[0]

    patterns = [
        r'<title>Index of /',                                # Apache-style
        r'<h1>Index of /',                                   # Apache-style H1
        r'\[To Parent Directory\]</A>',                      # IIS-style
        r'<title>' + re.escape(host) + r' - /</title>',      # Lighttpd-style
        r'_sort=\'name\';SortDirsAndFilesName\(\)',          # h5ai
        r'<body[^>]*class="[^"]*dufs[^"]*"',                 # DUFS body
        r'<footer[^>]*>Generated by dufs',                   # DUFS footer
        r'<script[^>]*src="[^"]*dufs[^"]*"',                 # DUFS JS
        # Caddy-style breadcrumb
        r'<div class="breadcrumbs">Folder Path</div>',
        r'<th><a href="\?C=N;O=D">Name</a></th><th><a href="\?C=M;O=A">Last modified</a></th><th><a href="\?C=S;O=A">Size</a></th><th><a href="\?C=D;O=A">Description</a></th>',
        r'<table class="sortable">\s*<thead>\s*<tr>\s*<th>Name\s*</th>\s*<th>Size\s*</th>\s*<th>Uploaded\s*</th>\s*<th>\s*</th>\s*</tr>',
        r'<title>Directory Listing</title>',
        r'<h1>Listing of /',
        r'Powered by <a class="autoindex_a" href="http://autoindex.sourceforge.net/">AutoIndex PHP Script</a>',
        r'<a href="\?C=N;O=D">\s*Name\s*</a>\s*<a href="\?C=M;O=A">\s*Last modified\s*</a>\s*<a href="\?C=S;O=A">\s*Size\s*</a>\s*<a href="\?C=D;O=A">\s*Description\s*</a>',
        r'<a href="\?C=N&amp;O=A">\s*File Name\s*</a>\s*&nbsp;\s*<a href="\?C=N&amp;O=D">\s*&nbsp;&darr;&nbsp;\s*</a></th>\s*<th style="width:20%">\s*<a href="\?C=S&amp;O=A">\s*File Size\s*</a>\s*&nbsp;\s*<a href="\?C=S&amp;O=D">\s*&nbsp;&darr;&nbsp;\s*</a>',
        r'<a href="\?C=N&amp;O=A">\s*File Name\s*</a>\s*(?:&nbsp;|\u00a0)\s*<a href="\?C=N&amp;O=D">\s*(?:&nbsp;|\u00a0)?(?:&darr;|\u2193)(?:&nbsp;|\u00a0)?\s*</a>[\s\S]*?<a href="\?C=S&amp;O=A">\s*File Size\s*</a>\s*(?:&nbsp;|\u00a0)\s*<a href="\?C=S&amp;O=D">\s*(?:&nbsp;|\u00a0)?(?:&darr;|\u2193)(?:&nbsp;|\u00a0)?\s*</a>',
        r'<meta\s+name="generator"\s+content="AList V\d+"\s*/?>',
        r'<meta\scontent="AList V\d+"\sname="generator"/?>',
        r'<div\s+id=["\']idx["\']>\s*<!--\s*do not remove\s*-->',
        r'<tr[^>]*class=["\']indexhead["\'][^>]*>.*Name.*Last modified.*Size.*Description',
        r'<pre>(?:\s*\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}\s+(?:AM|PM)?\s+\d+\s+<a href="[^"]+">[^<]+</a>\s*<br>\s*){2,}</pre>',
        r'<html><head><title>' + hostnp + r' - /[^<]*</title></head><body><h1>' + hostnp + r' - /[^<]*</h1>',
        r'<meta\s+name=["\']description["\']\s+content=["\']Yet another directory listing, powered by Directory Lister\.["\']\s*/?>',
        r'<meta\scontent="Yet\sanother\sdirectory\slisting,\spowered\sby\sDirectory\sLister\."\sname="description"/>',
        r'<title>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*-\s*/</title>',
        r'<title>Index of .*?</title>',
        r'<h1>Index of .*?</h1>',
        r'<h1>文件索引.*?</h1>',
        r'Directory listing for .*',
        r'<ListBucketResult\s+xmlns=[\'\"].*?[\'\"]>',
        r'<tr\s+class=["\']indexhead["\']>\s*<th\s+class=["\']indexcolicon["\']>\s*<img\s+src=["\']/icons/blank\.gif["\']\s+alt=["\']\[ICO\]["\']\s*/?>\s*</th>\s*<th\s+class=["\']indexcolname["\']>\s*<a\s+href=["\']\?C=N;O=A["\']>\s*Name\s*</a>\s*</th>\s*<th\s+class=["\']indexcollastmod["\']>\s*<a\s+href=["\']\?C=M;O=A["\']>\s*Last\s+modified\s*</a>\s*</th>\s*<th\s+class=["\']indexcolsize["\']>\s*<a\s+href=["\']\?C=S;O=A["\']>\s*Size\s*</a>\s*</th>\s*</tr>',
        r'\.calibreRangeWrapper',
        r'<body\sstyle="font-size:medium">[a-z]*\sFolder\s*\t*<a\shref="/list\?dir=1">',
        r'<img\s+[^>]*alt="\[PARENTDIR\]"[^>]*>',
        r'<img\s+[^>]*alt="\[DIR\]"[^>]*>',
        r'\.\.\/">Parent Directory<\/a>',
        r'\.\.\/">Parent directory\/<\/a>',
        r'https:\/\/github\.com\/DirectoryLister\/DirectoryLister',
        r'<h1>Directory \/',
        r'powered by h5ai',
        r'<h1>Directory: \/',
        r'<hr>Directory Listing Script &copy;',
    ]

    for pat in patterns:
        if re.search(pat, content, re.IGNORECASE):
            print(f'### Is open directory - {content_url} - matched pattern: {pat}')
            return True
    return False


def function_for_url(regexp_list):
    """
    Decorator factory that registers a function to handle URLs matching given regex patterns.
    This decorator allows you to associate a handler function with specific URL patterns
    in the crawler. When a URL matches any of the provided regular expressions, the
    decorated function will be called to process that URL.

    Args:
        regexp_list (list): List of regex pattern strings that define which URLs
                           this function should handle. Patterns are compiled with
                           case-insensitive and Unicode flags.

    Returns:
        function: A decorator function that registers the decorated function
                 as a URL handler and adds it to the global url_functions list.

    Example:
        @function_for_url([r'.*pdf$', r'.*doc$'])
        def handle_documents(url, content):
            # Process PDF and DOC files
            pass
    """
    def get_url_function(f):
        for regexp in regexp_list:
            url_functions.append((re.compile(regexp, flags=re.I | re.U), f))
        return f
    return get_url_function


# url unsafe {}|\^~[]`
@function_for_url(
    [
        r"^(\/|\.\.\/|\.\/)",
        r"^[0-9\-\./\?=_\&\s%@<>\(\);\+!,\w\$\'–’—”“a°§£Ã¬´c�í¦a]+$",
        r"^[0-9\-\./\?=_\&\s%@<>\(\);\+!,\w\$\'–’—”“a°§£Ã¬´c]*[\?\/][0-9\-\./\?=_\&\s%@<>\(\);\+!,\w\$\'–’—”“a°§£Ã¬:\"¶c´™*]+$",
    ]
)
def relative_url(args):
    """
    Handle relative URLs found during crawling and convert them to absolute URLs.

    regex no need to escape '!', '"', '%', "'", ',', '/', ':', ';', '<', '=', '>', '@', and "`"

    This function processes URLs that are relative to the current page (starting with
    '/', '../', or './') or contain various characters commonly found in web URLs.
    It converts relative URLs to absolute URLs using the parent page's URL as a base,
    then adds the new URL to the database for future crawling.

    The function is registered to handle URLs matching these patterns:
    - Relative paths starting with '/', '../', or './'
    - URLs containing alphanumeric characters, common punctuation, and special
      characters typically found in web addresses
    - Complex URLs with query parameters and fragments

    Args:
        args (dict): Dictionary containing:
            - 'url' (str): The relative URL to process
            - 'parent_url' (str): The absolute URL of the page containing this link
            - 'db': Database connection object for storing new URLs

    Returns:
        bool: Always returns True to indicate successful processing

    Note:
        URLs are marked as unvisited when added to the database. The regex patterns
        include various Unicode characters and symbols to handle international URLs
        and special formatting characters found in web content.
    """
    out_url = urljoin(args['parent_url'], args['url'])
    parent_host = urlsplit(args['parent_url'])[1]
    db_insert_if_new_url(url=out_url, visited=False, source="relative_url", parent_host=parent_host, db=args['db'])
    return True


@function_for_url(
    [
        r"(\{|\[|\||\}|\]|\~|\^|\\)",
    ]
)
def unsafe_character_url(args):
    """
    Handle URLs containing unsafe or problematic characters by ignoring them.

    This function is registered to catch URLs that contain characters which are
    considered unsafe or problematic for URL processing, specifically:
    - Curly braces: { }
    - Square brackets: [ ]
    - Pipe symbol: |
    - Tilde: ~
    - Caret: ^
    - Backslash: \

    These characters can cause issues in URL parsing, are often found in malformed
    URLs, or may indicate URLs that are not standard web addresses (e.g., template
    variables, placeholder text, or escaped content).

    Args:
        args (dict): Dictionary containing URL processing arguments:
            - 'url' (str): The URL containing unsafe characters
            - 'parent_url' (str): The URL of the parent page
            - 'db': Database connection object

    Returns:
        bool: Always returns True, effectively filtering out these URLs by
              not processing them further (no database insertion occurs)

    Note:
        This function acts as a URL filter - it accepts these URLs but doesn't
        process them, preventing potentially problematic URLs from being added
        to the crawling queue.
    """
    return True


@function_for_url(url_all_others_regex)
def do_nothing_url(args):
    """
    Placeholder function that handles URLs matching catch-all patterns without processing.

    This function is registered to handle URLs that match patterns defined in
    url_all_others_regex but don't require any specific processing. It serves as
    a no-op handler that prevents these URLs from being processed by other functions
    while keeping the regex patterns available as reference.

    The function acts as a documentation mechanism, preserving regex patterns that
    might be useful for future development or customization without actively
    processing the matched URLs.

    Args:
        args (dict): Dictionary containing URL processing arguments:
            - 'url' (str): The URL that matched the catch-all patterns
            - 'parent_url' (str): The URL of the parent page
            - 'db': Database connection object

    Returns:
        bool: Always returns True to indicate the URL was "handled" (by doing nothing)

    Note:
        This function serves as a template - developers can replace this implementation
        with custom logic for handling specific URL patterns as needed. The regex
        patterns in url_all_others_regex are preserved as a guideline for future
        functionality.
    """
    return True


@function_for_url([r"^https*://", r"^ftp://"])
def full_url(args):
    """
    Handle absolute URLs (HTTP, HTTPS, FTP) found during crawling.

    This function processes fully-qualified URLs that include a complete protocol
    and domain. It extracts the parent host information and adds the URL to the
    crawling database for future processing.

    The function is registered to handle URLs matching these patterns:
    - HTTP URLs: http://example.com/path
    - HTTPS URLs: https://example.com/path
    - FTP URLs: ftp://example.com/path

    Args:
        args (dict): Dictionary containing:
            - 'url' (str): The absolute URL to process
            - 'parent_url' (str): The URL of the page containing this link
            - 'db': Database connection object for storing new URLs

    Returns:
        bool: Always returns True to indicate successful processing

    Note:
        URLs are marked as unvisited when added to the database. The parent_host
        is extracted from the parent_url to track the source of discovered links,
        which can be useful for crawling analytics and avoiding infinite loops.
    """
    parent_host = urlsplit(args['parent_url'])[1]
    db_insert_if_new_url(url=args['url'], source="full_url", visited=False, parent_host=parent_host, db=args['db'])
    return True


@function_for_url(
    [
        r"^(mailto:|maillto:|maito:|mail:|malito:|mailton:|\"mailto:|emailto:|maltio:|mainto:|E\-mail:|mailtfo:|mailtp:|mailtop:|mailo:|mail to:|Email para:|email :|email:|E-mail: |mail-to:|maitlo:|mail.to:)"
    ]
)
def email_url(args):
    """
    Extract and validate email addresses from mailto links and similar email schemes.

    This function processes URLs that contain email addresses using various mailto
    schemes, including common misspellings and variations. It extracts the email
    address, validates its format, and stores it in the database if valid.

    The function handles numerous mailto variations including:
    - Standard: mailto:, mail:, email:
    - Common typos: maillto:, maito:, malito:, maltio:, etc.
    - Multi-language: "Email para:", "E-mail:", etc.
    - Malformed: mailton:, mailtfo:, mail.to:, etc.

    Args:
        args (dict): Dictionary containing:
            - 'url' (str): The mailto URL to process
            - 'parent_url' (str): The URL of the page containing this email link
            - 'db': Database connection object for storing email data

    Returns:
        bool: True if a valid email address was found and stored, False otherwise

    Process:
        1. Uses regex to match and extract email schemes (case-insensitive)
        2. Extracts the email address portion after the scheme
        3. Validates email format using standard email regex pattern
        4. If valid, stores the parent URL and email address in database
        5. Returns success/failure status

    Note:
        Only stores emails that pass basic format validation. The parent_url
        is stored rather than the mailto URL itself, as it represents the
        source page where the email was found.
    """
    address_search = re.search(
        r"^(mailto:|maillto:|maito:|mail:|malito:|mailton:|\"mailto:|emailto:|maltio:|mainto:|E\-mail:|mailtfo:|mailtp:|mailtop:|mailo:|mail to:|Email para:|email :|email:|E-mail: |mail-to:|maitlo:|mail.to:)(.*)",
        args['url'],
        flags=re.I | re.U,
    )
    if address_search:
        address = address_search.group(2)
        if re.search(
            r"^([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+$",
            address,
        ):
            parent_host = urlsplit(args['parent_url'])[1]
            db_insert_if_new_url(
                    url=args['parent_url'],
                    email=address,
                    source='email_url',
                    parent_host=parent_host,
                    db=args['db']
                )
            return True
        else:
            return False
    else:
        return False


def get_links(soup, content_url, db):
    """
    Extract and process all hyperlinks from a parsed HTML page.

    This function finds all anchor tags (<a>) in the provided BeautifulSoup object,
    extracts their href attributes, and processes each URL through the crawler's
    URL handling system. It applies filtering based on allow/block lists and
    routes URLs to appropriate handler functions.

    Args:
        soup (BeautifulSoup): Parsed HTML content containing anchor tags
        content_url (str): The URL of the current page being processed
        db: Database connection object for storing discovered URLs

    Returns:
        bool: Always returns True indicating successful processing

    Process:
        1. Finds all anchor tags in the HTML
        2. Extracts and sanitizes href attributes
        3. Handles relative URLs by using the current page's host
        4. Applies host and URL filtering (allow/block lists)
        5. Routes URLs through registered handler functions via url_functions
        6. For unmatched URLs, prints debug info and optionally adds to database
           if BE_GREEDY flag is enabled

    Filtering:
        - Skips non-string href values
        - Applies host block/allow list filtering
        - Applies URL-specific block list filtering
        - Only processes URLs from allowed hosts

    Note:
        Contains commented code for extracting patterns from JavaScript,
        which can be uncommented for additional link discovery from scripts.
        The BE_GREEDY flag controls whether unmatched URLs are still added
        to the crawling queue for potential future processing.
    """
    # If you want to grep some patterns, use the code below.
    # pattern=r'"file":{".*?":"(.*?)"}'
    # for script in soup.find_all('script',type="text/javascript"):
    #    if re.search(pattern,str(script)):
    #        print(re.search(pattern,str(script))[1])
    tags = soup("a")
    for tag in tags:
        url = tag.get("href", None)

        if not isinstance(url, str):
            continue
        else:
            url = sanitize_url(url)
        found = False
        host = urlsplit(url)[1]
        # The block below ensures that if link takes to a internal directory
        # of the server, it will use the original host
        if host == '':
            host = urlsplit(content_url)[1]
        if (
            not is_host_block_listed(host)
            and is_host_allow_listed(host)
            and not is_url_block_listed(url)
        ):
            for regex, function in url_functions:
                m = regex.search(url)
                if m:
                    found = True
                    function({'url': url, 'parent_url': content_url, 'db': db})
                    continue
            if not found:
                out_url = urljoin(content_url, url)
                print("Unexpected URL -{}- Ref -{}-".format(url, content_url))
                print("Unexpected URL. Would this work? -{}-".format(out_url))
                parent_host = urlsplit(content_url)[1]
                if BE_GREEDY:
                    db_insert_if_new_url(url=out_url,
                                         source="get_links",
                                         visited=False,
                                         parent_host=parent_host,
                                         db=db)
    return True


def function_for_content_type(regexp_list):
    """
    Decorator factory that registers a function to handle specific content types.

    This decorator allows you to associate a handler function with content types
    matching given regex patterns. When content with a matching Content-Type header
    is encountered during crawling, the decorated function will be called to
    process that content.

    Args:
        regexp_list (list): List of regex pattern strings that define which
                           content types this function should handle. Patterns
                           are compiled with case-insensitive and Unicode flags.

    Returns:
        function: A decorator function that registers the decorated function
                 as a content type handler and adds it to the global
                 content_type_functions list.

    Note:
        Similar to function_for_url but operates on HTTP Content-Type headers
        rather than URL patterns. This allows content-based routing regardless
        of the URL structure.
    """
    def get_content_type_function(f):
        for regexp in regexp_list:
            content_type_functions.append((re.compile(regexp, flags=re.I | re.U), f))
        return f
    return get_content_type_function


def get_directory_tree(url):
    """
    Generate a list of parent directory URLs from a given URL path.

    This function creates URLs for all parent directories in the path hierarchy,
    which is useful for directory traversal during web crawling. It builds URLs
    by progressively removing path segments from the end, creating a breadcrumb
    trail of parent directories.

    Args:
        url (str): The full URL to extract directory tree from
                  (e.g., "https://example.com/path/to/file.html")

    Returns:
        list: List of parent directory URLs in descending order from immediate
              parent to root directory

    Process:
        1. Extracts scheme and hostname (preserving port if present)
        2. URL-decodes the path to handle encoded characters
        3. Splits path into components using PurePosixPath
        4. Iteratively removes trailing path segments to build parent URLs
        5. Returns list of parent directory URLs

    Note:
        URLs are unquoted to handle percent-encoded paths correctly.
        The function assumes POSIX-style paths with forward slashes.
        Root directory and the original URL itself are not included in results.
    """
    # Host will have scheme, hostname and port
    host = '://'.join(urlsplit(url)[:2])
    dtree = []
    for iter in range(1, len(PurePosixPath(unquote(urlparse(url).path)).parts[0:])):
        dtree.append(str(host+'/'+'/'.join(PurePosixPath(unquote(urlparse(url).path)).parts[1:-iter])))
    return dtree


def insert_directory_tree(content_url, db):
    """
    Insert all parent directory URLs of a given URL into the crawling database.

    This function generates and stores all parent directory URLs for potential
    crawling, enabling directory traversal and discovery of additional content
    that might not be linked from the current page. It's useful for exploring
    web server directory structures systematically.

    Args:
        content_url (str): The source URL whose parent directories should be added
                          (e.g., "https://example.com/docs/files/document.pdf")
        db: Database connection object for storing URLs

    Process:
        1. Extracts the parent host from the source URL
        2. Generates all parent directory URLs using get_directory_tree()
        3. Sanitizes each directory URL
        4. Inserts each directory URL into the database as unvisited
        5. Marks all entries with source "insert_directory_tree" for tracking

    Example:
        For URL "https://site.com/blog/2023/posts/article.html", this will add:
        - https://site.com/blog/2023/posts/
        - https://site.com/blog/2023/
        - https://site.com/blog/

    Note:
        All inserted URLs are marked as unvisited and will be processed by the
        crawler in subsequent iterations. The parent_host is preserved to
        maintain crawling context and enable proper filtering. Empty strings
        are used for words and content_type since directories haven't been
        crawled yet.
    """
    parent_host = urlsplit(content_url)[1]
    for url in get_directory_tree(content_url):
        url = sanitize_url(url)
        db_insert_if_new_url(
                url=url, words='',
                content_type='',
                visited=False,
                source="insert_directory_tree",
                parent_host=parent_host,
                db=db)


@function_for_content_type(content_type_html_regex)
def content_type_download(args):
    """
    Process HTML content by extracting links and storing page data in the database.

    This function handles HTML pages discovered during crawling by parsing the content,
    extracting all hyperlinks for further crawling, and storing various representations
    of the page content based on configuration flags. It includes robust error handling
    for parsing failures and encoding issues.

    Args:
        args (dict): Dictionary containing:
            - 'content' (str/bytes): HTML content to process
            - 'url' (str): URL of the page being processed
            - 'content_type' (str): HTTP Content-Type header value
            - 'parent_host' (str): Host of the referring page
            - 'db': Database connection object

    Returns:
        bool: True if processing succeeded, False if parsing failed

    Process:
        1. Decodes content from bytes to string if necessary (UTF-8 with error replacement)
        2. Parses HTML using BeautifulSoup with html.parser
        3. Extracts all hyperlinks using get_links() for continued crawling
        4. Conditionally extracts content based on configuration flags:
           - EXTRACT_WORDS: Extracts text words from the page
           - EXTRACT_RAW_WEBCONTENT: Stores raw HTML (truncated to MAX_WEBCONTENT_SIZE)
           - EXTRACT_MIN_WEBCONTENT: Stores minimal content representation
        5. Detects if page is an open directory listing
        6. Stores all extracted data in the database

    Error Handling:
        - UnboundLocalError: Handles variable scope issues
        - ParserRejectedMarkup: Handles malformed HTML that BeautifulSoup cannot parse
        - Both exceptions result in database entry with empty content fields

    Note:
        Content is truncated to MAX_WEBCONTENT_SIZE to prevent database bloat.
        All pages are marked as visited=True after processing. The function
        serves as the main HTML content processor in the crawling pipeline.
    """
    try:
        content = args['content']
        # Ensure content is decoded properly
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='replace')
        soup = BeautifulSoup(content, "html.parser")
    except UnboundLocalError as e:
        print(e)
        db_insert_if_new_url(
                url=args['url'],
                content_type=args['content_type'],
                isopendir=False,
                visited=True,
                words='',
                min_webcontent='',
                raw_webcontent='',
                source='content_type_html_regex.exception',
                parent_host=args['parent_host'],
                db=args['db'])
        return False
    except bs4.builder.ParserRejectedMarkup as e:
        db_insert_if_new_url(
                url=args['url'],
                content_type=args['content_type'],
                isopendir=False,
                visited=True,
                words='',
                min_webcontent='',
                raw_webcontent='',
                source='content_type_html_regex.exception',
                parent_host=args['parent_host'],
                db=args['db'])
        print(e)
        return False

    get_links(soup, args['url'], args['db'])
    words = ''
    min_webcontent = ''
    raw_webcontent = ''
    if EXTRACT_WORDS:
        words = get_words_from_soup(soup)

    if EXTRACT_RAW_WEBCONTENT:
        raw_webcontent = str(soup)[:MAX_WEBCONTENT_SIZE]

    if EXTRACT_MIN_WEBCONTENT:
        min_webcontent = get_min_webcontent(soup)[:MAX_WEBCONTENT_SIZE]

    isopendir = is_open_directory(str(soup), args['url'])
    db_insert_if_new_url(
            url=args['url'],
            content_type=args['content_type'],
            isopendir=isopendir,
            visited=True,
            words=words,
            min_webcontent=min_webcontent,
            raw_webcontent=raw_webcontent,
            source='content_type_html_regex',
            parent_host=args['parent_host'],
            db=args['db'])
    return True


@function_for_content_type(content_type_plain_text_regex)
def content_type_plain_text(args):
    """
    Process plain text content by extracting words and storing in the database.

    This function handles plain text files discovered during crawling by optionally
    extracting words for indexing and storing the processed information in the
    database. It's designed for content types like text/plain, text/css, etc.

    Args:
        args (dict): Dictionary containing:
            - 'content' (str): Plain text content to process
            - 'url' (str): URL of the text file being processed
            - 'content_type' (str): HTTP Content-Type header value
            - 'parent_host' (str): Host of the referring page
            - 'db': Database connection object

    Returns:
        bool: Always returns True indicating successful processing

    Process:
        1. Conditionally extracts words from text content if EXTRACT_WORDS is enabled
        2. Stores the URL and metadata in the database
        3. Marks the content as visited and not an open directory

    Configuration:
        - EXTRACT_WORDS: If True, extracts and stores searchable words from content
        - If False, words field remains empty to save storage space

    Note:
        Unlike HTML processing, this function doesn't extract links since plain
        text files typically don't contain hyperlinks. The content is processed
        as-is without parsing or markup interpretation. All entries are marked
        with source 'content_type_plain_text_regex' for tracking purposes.
    """
    words = ''
    if EXTRACT_WORDS:
        words = get_words(args['content'])
    db_insert_if_new_url(
            url=args['url'],
            content_type=args['content_type'],
            isopendir=False,
            visited=True,
            words=words,
            source='content_type_plain_text_regex',
            parent_host=args['parent_host'],
            db=args['db'])
    return True


@function_for_content_type(content_type_image_regex)
def content_type_images(args):
    """
    Processes image content detected by content type and performs optional actions
    such as saving, categorizing as NSFW, and recording metadata in the database.

    This function is triggered for URLs whose content type matches image patterns.
    It attempts to load the image, compute its resolution, and—depending on the
    configuration flags—save the image and classify it using an NSFW detection model.

    Parameters:
        args (dict): A dictionary with the following keys:
            - 'content' (bytes): The raw image content.
            - 'url' (str): The URL of the image.
            - 'content_type' (str): MIME type of the image.
            - 'parent_host' (str): The domain the image was found on.
            - 'db' (sqlite3.Connection): Database connection used for inserting metadata.

    Returns:
        bool:
            - True if the image was successfully processed and metadata inserted.
            - False if the image could not be opened, was corrupted, or raised known exceptions.

    Behavior:
        - If the image can't be opened, logs the attempt and returns False.
        - Converts certain image modes (e.g., CMYK or palette with transparency) to RGB/RGBA.
        - Saves the image if DOWNLOAD_ALL_IMAGES is set.
        - If CATEGORIZE_NSFW is enabled and the image resolution is above MIN_NSFW_RES:
            - Runs NSFW classification and logs the NSFW score.
            - Saves the image to SFW_FOLDER or NSFW_FOLDER based on probability thresholds.
        - Always logs the URL and image metadata (resolution, content type) to the database.

    Exceptions Handled:
        - PIL.UnidentifiedImageError: Unreadable or unsupported image format.
        - PIL.Image.DecompressionBombError: Exception for extremely large images.
        - OSError: Any general OS-related error while processing the image.

    Global Dependencies:
        - `model`: NSFW detection model used when CATEGORIZE_NSFW is enabled.
        - `IMAGES_FOLDER`, `NSFW_FOLDER`, `SFW_FOLDER`: Directories for saving images.
        - `CATEGORIZE_NSFW`, `DOWNLOAD_ALL_IMAGES`, `DOWNLOAD_NSFW`, `DOWNLOAD_SFW`:
          Configuration flags controlling feature behavior.
        - `MIN_NSFW_RES`, `NSFW_MIN_PROBABILITY`: Thresholds for classification logic.
    """
    global model
    npixels = 0
    if CATEGORIZE_NSFW or DOWNLOAD_ALL_IMAGES:
        try:
            img = Image.open(BytesIO(args['content']))
            width, height = img.size
            npixels = width * height
            nsfw_probability = 0
            if img.mode == "CMYK":
                img = img.convert("RGB")
            # Check if it's a palette-based image with transparency
            if img.mode == "P" and "transparency" in img.info:
                # Convert to RGBA to handle transparency properly
                img = img.convert("RGBA")
            filename = hashlib.sha512(img.tobytes()).hexdigest() + ".png"
        except UnidentifiedImageError as e:
            # SVG using cairo in the future
            db_insert_if_new_url(
                    url=args['url'],
                    content_type=args['content_type'],
                    source='content_type_images',
                    isopendir=False,
                    visited=True,
                    parent_host=args['parent_host'],
                    resolution=npixels,
                    db=args['db'])
            return False
        except Image.DecompressionBombError as e:
            db_insert_if_new_url(
                    url=args['url'],
                    content_type=args['content_type'],
                    source='content_type_images',
                    isopendir=False,
                    visited=True,
                    parent_host=args['parent_host'],
                    resolution=npixels,
                    db=args['db'])
            return False
        except OSError:
            db_insert_if_new_url(
                    url=args['url'],
                    content_type=args['content_type'],
                    source='content_type_images',
                    isopendir=False,
                    visited=True,
                    parent_host=args['parent_host'],
                    resolution=npixels,
                    db=args['db'])
            return False
        if DOWNLOAD_ALL_IMAGES:
            img.save(IMAGES_FOLDER+'/' + filename, "PNG")
        if CATEGORIZE_NSFW and npixels > MIN_NSFW_RES:
            image = n2.preprocess_image(img, n2.Preprocessing.YAHOO)
            inputs = np.expand_dims(image, axis=0)
            predictions = model.predict(inputs, verbose=0)
            sfw_probability, nsfw_probability = predictions[0]
            db_insert_if_new_url(
                    args['url'],
                    content_type=args['content_type'],
                    source='content_type_images',
                    visited=True,
                    parent_host=args['parent_host'],
                    isnsfw=nsfw_probability,
                    isopendir=False,
                    resolution=npixels,
                    db=args['db'])
            if nsfw_probability > NSFW_MIN_PROBABILITY:
                print('porn {} {}'.format(nsfw_probability, args['url']))
                if DOWNLOAD_NSFW:
                    img.save(NSFW_FOLDER + '/' + filename, "PNG")
            else:
                if DOWNLOAD_SFW:
                    img.save(SFW_FOLDER + '/' + filename, "PNG")
    db_insert_if_new_url(
            url=args['url'],
            content_type=args['content_type'],
            source='content_type_images',
            isopendir=False,
            visited=True,
            parent_host=args['parent_host'],
            resolution=npixels,
            db=args['db'])
    return True


@function_for_content_type(content_type_midi_regex)
def content_type_midis(args):
    """
    Handles MIDI files detected by content type during crawling.

    This function is triggered for URLs whose content type matches a MIDI-specific regex.
    It performs the following actions:

    1. Inserts the URL into the database if it's not already present.
    2. If MIDI downloading is enabled (controlled by `DOWNLOAD_MIDIS`), it:
        - Sanitizes the URL filename to ensure it's safe for the filesystem.
        - Truncates the filename if it's too long, appending a SHA-256 hash for uniqueness.
        - Writes the MIDI content to a local file inside the `MIDIS_FOLDER` directory.

    Args:
        args (dict): A dictionary containing the following keys:
            - 'url' (str): The URL of the MIDI file.
            - 'content_type' (str): The MIME type of the content.
            - 'content' (bytes): The raw content of the MIDI file.
            - 'parent_host' (str): The parent host from which the URL was discovered.
            - 'db' (sqlite3.Connection or similar): Database connection object.

    Returns:
        bool: Always returns True to signal successful processing.

    Notes:
        - If `DOWNLOAD_MIDIS` is False, the function skips the download step.
        - Filenames are made safe and unique using regex cleanup and SHA-256 hashing.
    """
    db_insert_if_new_url(
        url=args['url'],
        content_type=args['content_type'],
        isopendir=False,
        visited=True,
        source='content_type_midis',
        parent_host=args['parent_host'],
        db=args['db']
    )
    if not DOWNLOAD_MIDIS:
        return True
    url = args['url']
    base_filename = os.path.basename(urlparse(url).path)
    try:
        decoded_name = unquote(base_filename)
    except Exception:
        decoded_name = base_filename
    # Separate extension (e.g., ".pdf")
    name_part, ext = os.path.splitext(decoded_name)
    # Sanitize both parts
    name_part = re.sub(r"[^\w\-.]", "_", name_part)
    ext = re.sub(r"[^\w\-.]", "_", ext)
    # Create URL hash prefix (always fixed length)
    url_hash = hashlib.sha256(url.encode()).hexdigest()
    # Max length for entire filename (255) minus hash + dash + extension + safety margin
    max_name_length = MAX_FILENAME_LENGTH - len(url_hash) - 1 - len(ext)
    if len(name_part) > max_name_length:
        name_part = name_part[:max_name_length - 3] + "..."
    safe_filename = f"{url_hash}-{name_part}{ext}"
    filepath = os.path.join(MIDIS_FOLDER, safe_filename)
    with open(filepath, "wb") as f:
        f.write(args['content'])
    return True


@function_for_content_type(content_type_audio_regex)
def content_type_audios(args):
    """
    Handles audio files identified by content type during crawling.

    This function is automatically invoked for URLs whose `Content-Type` matches the
    `content_type_audio_regex` pattern. It performs the following tasks:

    1. Inserts the URL into the database if it's not already recorded.
    2. If audio downloading is enabled via the `DOWNLOAD_AUDIOS` flag:
        - Extracts and decodes the filename from the URL.
        - Sanitizes the filename to remove unsafe characters.
        - Truncates the name if necessary, appending a SHA-256 hash to ensure uniqueness.
        - Saves the audio content to a file in the `AUDIOS_FOLDER` directory.

    Args:
        args (dict): A dictionary containing:
            - 'url' (str): The URL of the audio file.
            - 'content_type' (str): MIME type of the content (e.g., "audio/mpeg").
            - 'content' (bytes): Binary data of the audio file.
            - 'parent_host' (str): The host from which this URL was discovered.
            - 'db' (sqlite3.Connection or compatible): Database connection for storing metadata.

    Returns:
        bool: Always returns True to indicate the content has been processed.

    Notes:
        - If `DOWNLOAD_AUDIOS` is False, the file is not saved, but the URL is still tracked.
        - The final filename is safe for filesystems and guaranteed to be unique using hashing.
    """
    db_insert_if_new_url(
        url=args['url'],
        content_type=args['content_type'],
        isopendir=False,
        visited=True,
        source='content_type_audios',
        parent_host=args['parent_host'],
        db=args['db']
    )
    if not DOWNLOAD_AUDIOS:
        return True
    url = args['url']
    base_filename = os.path.basename(urlparse(url).path)
    try:
        decoded_name = unquote(base_filename)
    except Exception:
        decoded_name = base_filename
    # Separate extension (e.g., ".pdf")
    name_part, ext = os.path.splitext(decoded_name)
    # Sanitize both parts
    name_part = re.sub(r"[^\w\-.]", "_", name_part)
    ext = re.sub(r"[^\w\-.]", "_", ext)
    # Create URL hash prefix (always fixed length)
    url_hash = hashlib.sha256(url.encode()).hexdigest()
    # Max length for entire filename (255) minus hash + dash + extension + safety margin
    max_name_length = MAX_FILENAME_LENGTH - len(url_hash) - 1 - len(ext)
    if len(name_part) > max_name_length:
        name_part = name_part[:max_name_length - 3] + "..."
    safe_filename = f"{url_hash}-{name_part}{ext}"
    filepath = os.path.join(AUDIOS_FOLDER, safe_filename)
    with open(filepath, "wb") as f:
        f.write(args['content'])
    return True


@function_for_content_type(content_type_video_regex)
def content_type_videos(args):
    """
    Handles video files identified by their content type during crawling.

    This function is triggered when a URL's content type matches the `content_type_video_regex`.
    It performs the following actions:

    1. Inserts the URL into the database if it hasn't already been recorded.
    2. If video downloading is enabled via the `DOWNLOAD_VIDEOS` flag:
        - Extracts and decodes the filename from the URL.
        - Sanitizes the filename to replace unsafe characters.
        - Truncates the filename if it's too long, preserving the extension.
        - Prepends a SHA-256 hash to ensure filename uniqueness and avoid collisions.
        - Saves the binary video content to a file within the `VIDEOS_FOLDER` directory.

    Args:
        args (dict): A dictionary containing:
            - 'url' (str): The URL of the video file.
            - 'content_type' (str): The MIME type of the content (e.g., "video/mp4").
            - 'content' (bytes): The raw binary content of the video file.
            - 'parent_host' (str): The domain where the video link was found.
            - 'db' (sqlite3.Connection or compatible): Database connection used to record the URL.

    Returns:
        bool: Always returns True, indicating the content has been processed.

    Notes:
        - If `DOWNLOAD_VIDEOS` is False, the video is not downloaded but metadata is still saved.
        - Filenames are made filesystem-safe and uniquely identifiable using SHA-256 hashes.
    """
    db_insert_if_new_url(
        url=args['url'],
        content_type=args['content_type'],
        isopendir=False,
        visited=True,
        source='content_type_videos',
        parent_host=args['parent_host'],
        db=args['db']
    )
    if not DOWNLOAD_VIDEOS:
        return True
    url = args['url']
    base_filename = os.path.basename(urlparse(url).path)
    try:
        decoded_name = unquote(base_filename)
    except Exception:
        decoded_name = base_filename
    # Separate extension (e.g., ".pdf")
    name_part, ext = os.path.splitext(decoded_name)
    # Sanitize both parts
    name_part = re.sub(r"[^\w\-.]", "_", name_part)
    ext = re.sub(r"[^\w\-.]", "_", ext)
    # Create URL hash prefix (always fixed length)
    url_hash = hashlib.sha256(url.encode()).hexdigest()
    # Max length for entire filename (255) minus hash + dash + extension + safety margin
    max_name_length = MAX_FILENAME_LENGTH - len(url_hash) - 1 - len(ext)
    if len(name_part) > max_name_length:
        name_part = name_part[:max_name_length - 3] + "..."
    safe_filename = f"{url_hash}-{name_part}{ext}"
    filepath = os.path.join(VIDEOS_FOLDER, safe_filename)
    with open(filepath, "wb") as f:
        f.write(args['content'])
    return True


@function_for_content_type(content_type_pdf_regex)
def content_type_pdfs(args):
    """
    Handles PDF files detected by content type during crawling.

    This function is automatically triggered for URLs whose `Content-Type` matches
    the `content_type_pdf_regex`. It carries out the following steps:

    1. Inserts the URL and its metadata into the database, marking it as visited.
    2. If `DOWNLOAD_PDFS` is enabled:
        - Extracts and decodes the filename from the URL path.
        - Sanitizes the filename by replacing unsafe characters with underscores.
        - Truncates overly long filenames while preserving the file extension.
        - Prepends a SHA-256 hash of the URL to ensure uniqueness.
        - Saves the binary PDF content to the `PDFS_FOLDER` directory.

    Args:
        args (dict): A dictionary containing:
            - 'url' (str): The URL pointing to the PDF file.
            - 'content_type' (str): The MIME type of the file (e.g., "application/pdf").
            - 'content' (bytes): The binary content of the PDF file.
            - 'parent_host' (str): The domain or IP from which the URL was found.
            - 'db' (sqlite3.Connection or compatible): Database connection object.

    Returns:
        bool: Always returns True to indicate successful processing.

    Notes:
        - If `DOWNLOAD_PDFS` is False, the file is not saved, but the URL is still logged in the DB.
        - The saved filename is safe for use in filesystems and uniquely identifies the source URL.
    """
    db_insert_if_new_url(
        url=args['url'],
        content_type=args['content_type'],
        isopendir=False,
        visited=True,
        source='content_type_pdfs',
        parent_host=args['parent_host'],
        db=args['db']
    )
    if not DOWNLOAD_PDFS:
        return True
    url = args['url']
    base_filename = os.path.basename(urlparse(url).path)
    try:
        decoded_name = unquote(base_filename)
    except Exception:
        decoded_name = base_filename
    # Separate extension (e.g., ".pdf")
    name_part, ext = os.path.splitext(decoded_name)
    # Sanitize both parts
    name_part = re.sub(r"[^\w\-.]", "_", name_part)
    ext = re.sub(r"[^\w\-.]", "_", ext)
    # Create URL hash prefix (always fixed length)
    url_hash = hashlib.sha256(url.encode()).hexdigest()
    # Max length for entire filename (255) minus hash + dash + extension + safety margin
    max_name_length = MAX_FILENAME_LENGTH - len(url_hash) - 1 - len(ext)
    if len(name_part) > max_name_length:
        name_part = name_part[:max_name_length - 3] + "..."
    safe_filename = f"{url_hash}-{name_part}{ext}"
    filepath = os.path.join(PDFS_FOLDER, safe_filename)
    with open(filepath, "wb") as f:
        f.write(args['content'])
    return True


@function_for_content_type(content_type_doc_regex)
def content_type_docs(args):
    """
    Handles document files (e.g., .doc, .docx) identified by content type during crawling.

    This function is called when a URL's `Content-Type` matches the `content_type_doc_regex`.
    It performs the following operations:

    1. Records the URL and its metadata in the database, marking it as visited.
    2. If `DOWNLOAD_DOCS` is enabled:
        - Extracts and decodes the filename from the URL path.
        - Sanitizes the filename by replacing unsafe characters.
        - Truncates the filename if necessary, while preserving the extension.
        - Prepends a SHA-256 hash of the URL to guarantee uniqueness.
        - Saves the document content as a binary file in the `DOCS_FOLDER` directory.

    Args:
        args (dict): A dictionary containing:
            - 'url' (str): The full URL of the document.
            - 'content_type' (str): The MIME type (e.g., "application/msword").
            - 'content' (bytes): Raw binary content of the document.
            - 'parent_host' (str): The originating host or domain.
            - 'db' (sqlite3.Connection or similar): Database connection used for storing metadata.

    Returns:
        bool: Always returns True to indicate the URL has been processed.

    Notes:
        - If `DOWNLOAD_DOCS` is False, the document will not be saved, but its metadata is still stored.
        - The filename is made safe and unique using SHA-256 hashing and regex sanitization.
    """
    db_insert_if_new_url(
        url=args['url'],
        content_type=args['content_type'],
        isopendir=False,
        visited=True,
        source='content_type_docs',
        parent_host=args['parent_host'],
        db=args['db']
    )
    if not DOWNLOAD_DOCS:
        return True
    url = args['url']
    base_filename = os.path.basename(urlparse(url).path)
    try:
        decoded_name = unquote(base_filename)
    except Exception:
        decoded_name = base_filename
    # Separate extension (e.g., ".pdf")
    name_part, ext = os.path.splitext(decoded_name)
    # Sanitize both parts
    name_part = re.sub(r"[^\w\-.]", "_", name_part)
    ext = re.sub(r"[^\w\-.]", "_", ext)
    # Create URL hash prefix (always fixed length)
    url_hash = hashlib.sha256(url.encode()).hexdigest()
    # Max length for entire filename (255) minus hash + dash + extension + safety margin
    max_name_length = MAX_FILENAME_LENGTH - len(url_hash) - 1 - len(ext)
    if len(name_part) > max_name_length:
        name_part = name_part[:max_name_length - 3] + "..."
    safe_filename = f"{url_hash}-{name_part}{ext}"
    filepath = os.path.join(DOCS_FOLDER, safe_filename)
    with open(filepath, "wb") as f:
        f.write(args['content'])
    return True


@function_for_content_type(content_type_database_regex)
def content_type_databases(args):
    """
    Handles database files (e.g., .sql, .mdb) identified by content type during crawling.

    This function is triggered when a URL's `Content-Type` matches the `content_type_database_regex`.
    It performs the following operations:

    1. Records the URL and associated metadata in the database, marking it as visited.
    2. If `DOWNLOAD_DATABASES` is enabled:
        - Extracts the filename from the URL path and attempts to decode it.
        - Sanitizes the filename to remove unsafe characters.
        - Truncates the filename if it's too long, preserving the extension.
        - Prepends a SHA-256 hash of the URL to guarantee uniqueness.
        - Saves the database file (in binary format) to the `DATABASES_FOLDER`.

    Args:
        args (dict): A dictionary containing:
            - 'url' (str): The URL pointing to the database file.
            - 'content_type' (str): The MIME type of the file (e.g., "application/sql").
            - 'content' (bytes): Binary content of the database file.
            - 'parent_host' (str): The domain or host where the link was found.
            - 'db' (sqlite3.Connection or compatible): A database connection object for metadata storage.

    Returns:
        bool: Always returns True to indicate successful processing.

    Notes:
        - If `DOWNLOAD_DATABASES` is False, the file is not saved, but the URL is still recorded.
        - The filename is sanitized and prefixed with a hash to ensure it's both safe and unique.
    """
    db_insert_if_new_url(
        url=args['url'],
        content_type=args['content_type'],
        isopendir=False,
        visited=True,
        source='content_type_databases',
        parent_host=args['parent_host'],
        db=args['db']
    )
    if not DOWNLOAD_DATABASES:
        return True
    url = args['url']
    base_filename = os.path.basename(urlparse(url).path)
    try:
        decoded_name = unquote(base_filename)
    except Exception:
        decoded_name = base_filename
    # Separate extension (e.g., ".pdf")
    name_part, ext = os.path.splitext(decoded_name)
    # Sanitize both parts
    name_part = re.sub(r"[^\w\-.]", "_", name_part)
    ext = re.sub(r"[^\w\-.]", "_", ext)
    # Create URL hash prefix (always fixed length)
    url_hash = hashlib.sha256(url.encode()).hexdigest()
    # Max length for entire filename (255) minus hash + dash + extension + safety margin
    max_name_length = MAX_FILENAME_LENGTH - len(url_hash) - 1 - len(ext)
    if len(name_part) > max_name_length:
        name_part = name_part[:max_name_length - 3] + "..."
    safe_filename = f"{url_hash}-{name_part}{ext}"
    filepath = os.path.join(DATABASES_FOLDER, safe_filename)
    with open(filepath, "wb") as f:
        f.write(args['content'])
    return True


@function_for_content_type(content_type_font_regex)
def content_type_fonts(args):
    """
    Handles font files (e.g., .ttf, .otf, .woff) identified by content type during crawling.

    This function is invoked when a URL's `Content-Type` matches the `content_type_font_regex`.
    It performs the following operations:

    1. Inserts the URL and its metadata into the database, marking it as visited.
    2. If `DOWNLOAD_FONTS` is enabled:
        - Extracts the filename from the URL path and decodes any URL-encoded characters.
        - Sanitizes the filename to replace unsafe characters with underscores.
        - Truncates overly long filenames, while preserving the extension.
        - Prepends a SHA-256 hash of the URL to ensure filename uniqueness.
        - Saves the font content (binary) to a file inside the `FONTS_FOLDER` directory.

    Args:
        args (dict): A dictionary with the following keys:
            - 'url' (str): The full URL pointing to the font file.
            - 'content_type' (str): The MIME type of the file (e.g., "font/woff2").
            - 'content' (bytes): The raw binary content of the font.
            - 'parent_host' (str): The domain or IP from which the font was discovered.
            - 'db' (sqlite3.Connection or compatible): Database connection for logging the metadata.

    Returns:
        bool: Always returns True, indicating the font file (or its metadata) was successfully processed.

    Notes:
        - If `DOWNLOAD_FONTS` is set to False, the font content will not be saved, but the URL will still be recorded.
        - The filename is constructed to be filesystem-safe and globally unique using hashing.
    """
    db_insert_if_new_url(
        url=args['url'],
        content_type=args['content_type'],
        isopendir=False,
        visited=True,
        source='content_type_fonts',
        parent_host=args['parent_host'],
        db=args['db']
    )
    if not DOWNLOAD_FONTS:
        return True
    url = args['url']
    base_filename = os.path.basename(urlparse(url).path)
    try:
        decoded_name = unquote(base_filename)
    except Exception:
        decoded_name = base_filename
    # Separate extension (e.g., ".pdf")
    name_part, ext = os.path.splitext(decoded_name)
    # Sanitize both parts
    name_part = re.sub(r"[^\w\-.]", "_", name_part)
    ext = re.sub(r"[^\w\-.]", "_", ext)
    # Create URL hash prefix (always fixed length)
    url_hash = hashlib.sha256(url.encode()).hexdigest()
    # Max length for entire filename (255) minus hash + dash + extension + safety margin
    max_name_length = MAX_FILENAME_LENGTH - len(url_hash) - 1 - len(ext)
    if len(name_part) > max_name_length:
        name_part = name_part[:max_name_length - 3] + "..."
    safe_filename = f"{url_hash}-{name_part}{ext}"
    filepath = os.path.join(FONTS_FOLDER, safe_filename)
    with open(filepath, "wb") as f:
        f.write(args['content'])
    return True


@function_for_content_type(content_type_torrent_regex)
def content_type_torrents(args):
    """
    Handles torrent files (e.g., .torrent) identified by content type during crawling.

    This function is executed when a URL's `Content-Type` matches the `content_type_torrent_regex`.
    It performs the following operations:

    1. Logs the URL and its associated metadata in the database, marking it as visited.
    2. If `DOWNLOAD_TORRENTS` is enabled:
        - Extracts the filename from the URL path and decodes any percent-encoded characters.
        - Sanitizes the filename to ensure filesystem safety by replacing problematic characters.
        - Truncates the filename if it's too long, ensuring the extension remains intact.
        - Prepends a SHA-256 hash of the URL to make the filename globally unique.
        - Writes the torrent file (binary content) to the `TORRENTS_FOLDER` directory.

    Args:
        args (dict): A dictionary containing:
            - 'url' (str): The URL pointing to the torrent file.
            - 'content_type' (str): The MIME type of the content (e.g., "application/x-bittorrent").
            - 'content' (bytes): Binary content of the torrent file.
            - 'parent_host' (str): Hostname or IP from which the URL was found.
            - 'db' (sqlite3.Connection or compatible): A database connection used to store metadata.

    Returns:
        bool: Always returns True, indicating the torrent URL has been processed.

    Notes:
        - If `DOWNLOAD_TORRENTS` is False, the file is not downloaded, but metadata is still logged.
        - The filename is made safe and unique using regex sanitization and SHA-256 hashing.
    """
    db_insert_if_new_url(
        url=args['url'],
        content_type=args['content_type'],
        isopendir=False,
        visited=True,
        source='content_type_torrents',
        parent_host=args['parent_host'],
        db=args['db']
    )
    if not DOWNLOAD_TORRENTS:
        return True
    url = args['url']
    base_filename = os.path.basename(urlparse(url).path)
    try:
        decoded_name = unquote(base_filename)
    except Exception:
        decoded_name = base_filename
    # Separate extension (e.g., ".pdf")
    name_part, ext = os.path.splitext(decoded_name)
    # Sanitize both parts
    name_part = re.sub(r"[^\w\-.]", "_", name_part)
    ext = re.sub(r"[^\w\-.]", "_", ext)
    # Create URL hash prefix (always fixed length)
    url_hash = hashlib.sha256(url.encode()).hexdigest()
    # Max length for entire filename (255) minus hash + dash + extension + safety margin
    max_name_length = MAX_FILENAME_LENGTH - len(url_hash) - 1 - len(ext)
    if len(name_part) > max_name_length:
        name_part = name_part[:max_name_length - 3] + "..."
    safe_filename = f"{url_hash}-{name_part}{ext}"
    filepath = os.path.join(TORRENTS_FOLDER, safe_filename)
    with open(filepath, "wb") as f:
        f.write(args['content'])
    return True


@function_for_content_type(content_type_compressed_regex)
def content_type_compresseds(args):
    """
    Handles compressed archive files (e.g., .zip, .gz, .rar) identified by content type during crawling.

    This function is invoked when a URL's `Content-Type` matches the `content_type_compressed_regex`.
    It performs the following steps:

    1. Records the URL and its metadata in the database, marking it as visited.
    2. If `DOWNLOAD_COMPRESSEDS` is enabled:
        - Extracts the base filename from the URL and attempts to decode it.
        - Sanitizes the filename by replacing any unsafe characters with underscores.
        - Truncates the filename if it exceeds the maximum safe length, preserving the extension.
        - Prepends a SHA-256 hash of the URL to ensure the filename is globally unique.
        - Writes the binary content of the compressed file to the `COMPRESSEDS_FOLDER` directory.

    Args:
        args (dict): A dictionary containing:
            - 'url' (str): The URL of the compressed file.
            - 'content_type' (str): The MIME type of the file (e.g., "application/zip").
            - 'content' (bytes): Binary content of the compressed file.
            - 'parent_host' (str): The host or domain from which the URL was discovered.
            - 'db' (sqlite3.Connection or compatible): Database connection used for logging metadata.

    Returns:
        bool: Always returns True, indicating the file (or its metadata) was successfully processed.

    Notes:
        - If `DOWNLOAD_COMPRESSEDS` is False, the content is skipped but the metadata is still saved.
        - Sanitization and hashing ensure all filenames are safe for the filesystem and uniquely traceable.
    """
    db_insert_if_new_url(
        url=args['url'],
        content_type=args['content_type'],
        isopendir=False,
        visited=True,
        source='content_type_compresseds',
        parent_host=args['parent_host'],
        db=args['db']
    )
    if not DOWNLOAD_COMPRESSEDS:
        return True
    url = args['url']
    base_filename = os.path.basename(urlparse(url).path)
    try:
        decoded_name = unquote(base_filename)
    except Exception:
        decoded_name = base_filename
    # Separate extension (e.g., ".pdf")
    name_part, ext = os.path.splitext(decoded_name)
    # Sanitize both parts
    name_part = re.sub(r"[^\w\-.]", "_", name_part)
    ext = re.sub(r"[^\w\-.]", "_", ext)
    # Create URL hash prefix (always fixed length)
    url_hash = hashlib.sha256(url.encode()).hexdigest()
    # Max length for entire filename (255) minus hash + dash + extension + safety margin
    max_name_length = MAX_FILENAME_LENGTH - len(url_hash) - 1 - len(ext)
    if len(name_part) > max_name_length:
        name_part = name_part[:max_name_length - 3] + "..."
    safe_filename = f"{url_hash}-{name_part}{ext}"
    filepath = os.path.join(COMPRESSEDS_FOLDER, safe_filename)
    with open(filepath, "wb") as f:
        f.write(args['content'])
    return True


@function_for_content_type(content_type_all_others_regex)
def content_type_ignore(args):
    """
    Handles all other content types not explicitly processed by specialized handlers.

    This function is invoked when a URL's `Content-Type` matches the
    `content_type_all_others_regex`, which serves as a fallback for any content types
    that don’t fall into specific categories like audio, video, PDF, etc.

    Its sole responsibility is to mark the URL as visited and record its metadata in the database
    without downloading or storing the content.

    Args:
        args (dict): A dictionary containing:
            - 'url' (str): The URL of the resource.
            - 'content_type' (str): The MIME type of the content.
            - 'parent_host' (str): The host where the URL was found.
            - 'db' (sqlite3.Connection or similar): Database connection used to store the metadata.

    Returns:
        bool: Always returns True to indicate the URL was processed and marked as visited.

    Notes:
        - This handler ensures complete tracking of crawled content types, even if they are ignored.
        - No content is downloaded or saved for these types.
    """
    db_insert_if_new_url(
            url=args['url'],
            visited=True,
            isopendir=False,
            content_type=args['content_type'],
            source='content_type_all_others_regex',
            parent_host=args['parent_host'],
            db=args['db']
        )
    return True


def sanitize_content_type(content_type):
    """
    Cleans and normalizes a raw Content-Type string.

    This function is used to sanitize HTTP `Content-Type` header values by:
    - Stripping leading/trailing whitespace.
    - Removing surrounding quotes, if any.
    - Stripping the "content-type:" prefix, in a case-insensitive and format-tolerant way.
    - Removing any additional metadata after a semicolon (e.g., charset info).
    - Removing all internal whitespace.

    This results in a clean MIME type string such as `application/pdf`, `audio/mpeg`, etc.

    Args:
        content_type (str): The raw Content-Type string extracted from headers.

    Returns:
        str: A cleaned and normalized content type string.
    """
    content_type = content_type.strip()
    content_type = content_type.rstrip()
    content_type = re.sub(r'^"(.*)"$', r"\1", content_type)  # remove surrounding quotes if present
    content_type = re.sub(r'^content-type: (.*)"$', r"\1", content_type)  # remove "content-type:" prefix
    content_type = re.sub(r'^content-type:(.*)"$', r"\1", content_type)  # remove "content-type:" prefix
    content_type = re.sub(r'^(.*?);.*$', r"\1", content_type)  # keep only the type/subtype part
    content_type = re.sub(r'\s+', '', content_type)  # remove any remaining spaces
    return content_type


def get_page(url, driver, db):
    """
    Fetches a web page using Selenium, processes its requests, and dispatches content
    to appropriate handlers based on content type. It also logs metadata and errors in the database.

    This function performs the following tasks:
    1. Loads the given URL using the provided Selenium `driver`.
    2. Iterates over all HTTP requests/responses made by the page.
    3. For each response:
        - If it's a redirect (301, 302, etc.), marks it as visited in the database.
        - If it includes a `Content-Type` header:
            - Attempts to decode the response body using appropriate encoding.
            - Handles specific decoding errors (e.g., Brotli, gzip, Unicode) by logging them with
              special tags in the database.
            - Sanitizes the `Content-Type` string.
            - If the host is allowed (not blocklisted), dispatches the content to the corresponding
              handler function registered for that MIME type.
            - If `HUNT_OPEN_DIRECTORIES` is enabled, checks for open directories and records them.
    4. Regardless of results, ensures the original URL and the final URL are marked as visited.

    Args:
        url (str): The original URL to be fetched and analyzed.
        driver (selenium-wire webdriver): A Selenium WebDriver instance with request capturing enabled.
        db (sqlite3.Connection or similar): The database connection used to store metadata and results.

    Returns:
        None

    Notes:
        - Content is dispatched to handler functions registered via `@function_for_content_type(...)`.
        - Known decoding errors are caught and logged under different `source` tags to help debugging.
        - Unrecognized content types are printed for inspection.
        - All URLs are recorded with their visit status, even if processing fails.
    """
    original_url = url
    driver = read_web(url, driver)  # Fetch the page using Selenium
    parent_host = urlsplit(url)[1]  # Get the parent host from the URL
    if driver:
        for request in driver.requests:
            if request.response:
                # Check if the response status code indicates redirection
                status_code = request.response.status_code
                if status_code in [301, 302, 303, 307, 308]:  # Redirection status codes
                    # Get the new URL from the Location header
                    db_insert_if_new_url(
                            url=url,
                            visited=True,
                            isopendir=False,
                            source='get_page.redirect',
                            parent_host=parent_host,
                            db=db
                        )
                # Continue with normal content processing
                if 'Content-Type' in request.response.headers:
                    url = request.url
                    host = urlsplit(url)[1]

                    try:
                        content = decode(request.response.body, request.response.headers.get('Content-Encoding', 'identity'))
                    except ValueError as e:  # 🛠️ Catch specific Brotli decompression failure
                        if "BrotliDecompress failed" in str(e):
                            db_insert_if_new_url(
                                    url=url,
                                    visited=True,
                                    source='BrotliDecompressFailed',
                                    parent_host=parent_host,
                                    db=db
                                )
                            continue
                        elif "LookupError when decoding" in str(e):
                            db_insert_if_new_url(
                                    url=url,
                                    visited=True,
                                    source='lookuperror',
                                    parent_host=parent_host,
                                    db=db
                                )
                            continue
                        elif "EOFError when decoding" in str(e):
                            db_insert_if_new_url(
                                    url=url,
                                    visited=True,
                                    source='EOFERROR',
                                    parent_host=parent_host,
                                    db=db
                                )
                            continue
                        elif "BadGzipFile when decoding" in str(e):
                            db_insert_if_new_url(
                                    url=url,
                                    visited=True,
                                    source='BadGzipFile',
                                    parent_host=parent_host,
                                    db=db
                                )
                            continue
                        elif "UnicodeDecodeError when decoding" in str(e):
                            db_insert_if_new_url(
                                    url=url,
                                    visited=True,
                                    source='UnicodeDecodeError',
                                    parent_host=parent_host,
                                    db=db
                                )
                            continue
                        else:
                            print(f"\033[91m !!!! This was not updated in the database, you need to deal with this error in the code function get_page [DECODE ERROR] {url} - {e} -\033[0m")
                            continue
                    content_type = request.response.headers['Content-Type']
                    content_type = sanitize_content_type(content_type)
                    host = urlsplit(url)[1]  # Extract host from the URL

                    if not is_host_block_listed(host) and is_host_allow_listed(host) and not is_url_block_listed(url):
                        if HUNT_OPEN_DIRECTORIES:
                            insert_directory_tree(url, db)

                        found = False
                        for regex, function in content_type_functions:
                            m = regex.search(content_type)
                            if m:
                                found = True
                                function({
                                    'url': url,
                                    'visited': True,
                                    'content_type': content_type,
                                    'content': content,
                                    'source': 'get_page',
                                    'words': '',
                                    'parent_host': parent_host,
                                    'db': db}
                                )
                        if not found:
                            print(f"UNKNOWN type -{url}- -{content_type}-")
        # force update on main url
        db_insert_if_new_url(
                url=url,
                visited=True,
                source='get_page.end',
                parent_host=parent_host,
                db=db
            )
    # force update on main url
    db_insert_if_new_url(
            url=original_url,
            visited=True,
            source='get_page.end.original',
            parent_host=parent_host,
            db=db
        )


class TimeoutException(Exception):
    """
    Custom exception raised when a timeout occurs.
    """
    pass


def break_after(seconds=60):
    """
    A decorator to limit the execution time of a function.

    It is particularly useful for interrupting long-running or hanging operations,
    such as web pages that stream or download large files indefinitely.

    Parameters:
    ----------
    seconds : int
        The maximum allowed execution time in seconds.

    Returns:
    -------
    function
        A wrapped function that will raise TimeoutException if it exceeds the time limit.
    """
    def timeout_handler(signum, frame):
        raise TimeoutException()

    def function_decorator(function):
        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(seconds)
            try:
                result = function(*args, **kwargs)
                signal.alarm(0)  # Clear the alarm if function returns in time
                return result
            except TimeoutException:
                print(
                    f"Oops, timeout: {seconds} sec reached in {function.__name__} with args={args} kwargs={kwargs}"
                )
                return None
        return wrapper
    return function_decorator


@break_after(MAX_DOWNLOAD_TIME)
def read_web(url, driver):
    """
    Loads a web page in the given Selenium driver, with a timeout applied.

    If the URL is HTTP (not HTTPS), it rewrites it to use a local HTTPS embed proxy.
    Useful for embedding external pages in a secure local environment.

    Parameters:
    ----------
    url : str
        The URL to be loaded.

    driver : selenium.webdriver
        The Selenium WebDriver instance.

    Returns:
    -------
    driver or False
        Returns the driver if successful, or False if an exception occurs.
    """
    try:
        if url.startswith('http://'):
            url = HTTPS_EMBED + url
        driver.get(url)
        return driver
    except Exception as e:
        print(e)
        return False


def initialize_driver():
    user_agent = UserAgent().random
    options = webdriver.ChromeOptions()
    options.add_argument(f'user-agent={user_agent}')
    prefs = {"download.default_directory": DIRECT_LINK_DOWNLOAD_FOLDER}
    if not CATEGORIZE_NSFW and not DOWNLOAD_ALL_IMAGES and not FORCE_IMAGE_LOAD:
        prefs["profile.managed_default_content_settings.images"] = 2  # disable images
    if BLOCK_CSS:
        prefs["profile.managed_default_content_settings.stylesheets"] = 2  # disable CSS
        prefs["profile.managed_default_content_settings.fonts"] = 2  # disable CSS
    options.add_experimental_option("prefs", prefs)
    if PERFORMANCE_OPTIMIZED:
        options.add_argument('--disable-extensions')
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-webgl')
        options.add_argument('--blink-settings=imagesEnabled=false')
    options.add_argument('--ignore-certificate-errors-spki-list')
    options.add_argument('--ignore-ssl-errors')
    # options.add_argument('--disable-webrtc')
    # options.add_argument('--disable-geolocation')
    # options.add_argument('--disable-infobars')
    # options.add_argument('--disable-popup-blocking')
    # options.add_argument('--disable-javascript')
    # options.add_argument('--proxy-server=http://your-proxy-server:port')
    # options.add_argument('--proxy-server=http://'+PROXY_HOST+':'PROXY_PORT)
    # The three options below must be enabled to allow navigating http sites
    # through the localhost https server
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("--disable-web-security")
    options.add_argument("--allow-running-insecure-content")
    driver = webdriver.Chrome(options=options)
    driver.set_window_size(SELENIUM_WIDTH, SELENIUM_HEIGHT)
    return driver


def crawler(db):
    for iteration in range(ITERATIONS):
        driver = initialize_driver()
        random_urls = get_random_unvisited_domains(db=db)
        for target_url in random_urls:
            if (
                not is_host_block_listed(target_url['host']) and
                is_host_allow_listed(target_url['host']) and
                not is_url_block_listed(target_url['url'])
            ):
                try:
                    print('    {}'.format(target_url['url']))
                    del driver.requests
                    get_page(target_url['url'], driver, db)
                    if HUNT_OPEN_DIRECTORIES:
                        insert_directory_tree(target_url['url'], db)
                except UnicodeEncodeError:
                    pass
        driver.quit()


def get_random_unvisited_domains(db, size=RANDOM_SITES_QUEUE):
    """
    Randomly selects between different spreading strategies based on weighted probabilities.

    Args:
        db: Database connection
        size: Number of domains to retrieve
    Returns:
        List of domains selected by the chosen method
    """
    # Default weights if none provided
    if METHOD_WEIGHTS is None:
        method_weights = {
            "web_search":   0,
            "fewest_urls":  1,
            "less_visited": 2,
            "oldest":       2,
            "host_prefix":  2,
            "random":       1
        }
    else:
        method_weights = METHOD_WEIGHTS

    # Filter out methods with zero weight
    active_methods = {name: weight for name, weight in method_weights.items() if weight > 0}

    # If no methods have weights > 0, return empty list
    if not active_methods:
        print("No active methods configured (all weights are 0)")
        return []

    # Normalize weights to sum to 1.0
    total_weight = sum(active_methods.values())
    normalized_weights = {name: weight/total_weight for name, weight in active_methods.items()}

    # Set up method mapping
    method_functions = {
        "web_search": lambda: get_urls_from_web_search(),
        "fewest_urls": lambda: get_least_covered_random_hosts(db, size=size),
        "less_visited": lambda: get_urls_from_least_visited_hosts(db, size=size),
        "oldest": lambda: get_oldest_unvisited_urls_from_bucket(db, size=size),
        "host_prefix": lambda: get_urls_by_random_bucket_and_host_prefix(db, size=size),
        "random": lambda: get_random_host_domains(db, size=size)
    }

    try:
        # Choose method based on normalized weights
        methods = list(normalized_weights.keys())
        weights = list(normalized_weights.values())
        chosen_method = random.choices(methods, weights=weights, k=1)[0]
        print(f'Selected method: \033[32m{chosen_method}\033[0m')
        return method_functions[chosen_method]()

    except NotFoundError as e:
        if "index_not_found_exception" in str(e):
            print("Elasticsearch index missing. Creating now...")
            db_create_database(INITIAL_URL, db=db)
            return []
        return []
    except RequestError as e:
        print("Elasticsearch request error:", e)
        return []
    except Exception as e:
        print(f"Unhandled error in get_random_unvisited_domains: {e}")
        return []


def get_urls_from_web_search():
    urls = []
    search_for = random.choice(SEARCH_WORDS)
    s = search(search_for, num_results=100, unique=True, safe=None)
    for url in s:
        if not url:
            continue
        parsed_url = urlparse(url)
        host = parsed_url.netloc
        urls.append({"url": url, "host": host})
    random.shuffle(urls)
    return urls


def get_least_covered_random_hosts(db, size=100):
    """Returns 'size' hosts from a random bucket with the fewest unvisited URLs, and one random URL per host."""
    random_bucket = random.randint(0, ELASTICSEARCH_RANDOM_BUCKETS - 1)
    print(f'    Selected bucket: \033[33m{random_bucket}\033[0m')

    # Step 1: Get hosts with fewest unvisited URLs
    agg_query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"term": {"random_bucket": random_bucket}},
                    {
                        "bool": {
                            "should": [
                                {"term": {"visited": False}},
                                {"bool": {"must_not": {"exists": {"field": "visited"}}}}
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ]
            }
        },
        "aggs": {
            "hosts": {
                "terms": {
                    "field": "host",
                    "size": size,
                    "order": {"_count": "asc"}  # Fewest unvisited URLs first
                }
            }
        }
    }

    agg_response = db.con.search(index=URLS_INDEX, body=agg_query)
    buckets = agg_response.get("aggregations", {}).get("hosts", {}).get("buckets", [])
    hosts = [bucket["key"] for bucket in buckets]
    for bucket in buckets:
        print('    \033[35m{}\t-{}-\033[0m'.format(bucket['doc_count'], bucket['key']))

    if not hosts:
        return []

    # Step 2: For each host, get one random unvisited URL
    results = []
    for host in hosts:
        query = {
            "size": 1,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"host": host}},
                        {"term": {"random_bucket": random_bucket}},
                        {
                            "bool": {
                                "should": [
                                    {"term": {"visited": False}},
                                    {"bool": {"must_not": {"exists": {"field": "visited"}}}}
                                ],
                                "minimum_should_match": 1
                            }
                        }
                    ]
                }
            },
            "sort": [
                {
                    "_script": {
                        "type": "number",
                        "script": {
                            "lang": "painless",
                            "source": "Math.random()"
                        },
                        "order": "asc"
                    }
                }
            ]
        }

        response = db.con.search(index=URLS_INDEX, body=query)
        hits = response.get("hits", {}).get("hits", [])
        if hits:
            results.append({
                "url": hits[0]["_source"]["url"],
                "host": host
            })

    if results:
        random.shuffle(results)
        return results

    return []


def get_urls_from_least_visited_hosts(db, size=100):
    """Fetch 1 truly unvisited URL per host from a random bucket."""
    random_bucket = random.randint(0, ELASTICSEARCH_RANDOM_BUCKETS - 1)
    print(f'    Selected bucket: \033[33m{random_bucket}\033[0m')

    query_body = {
        "size": size,
        "query": {
            "bool": {
                "must": [
                    {"term": {"random_bucket": random_bucket}},
                    {
                        "bool": {
                            "should": [
                                {"term": {"visited": False}},
                                {"bool": {"must_not": {"exists": {"field": "visited"}}}}
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ]
            }
        },
        "collapse": {
            "field": "host",
            "inner_hits": {
                "name": "least_visited_hit",
                "size": 1,
                "sort": [
                    {
                        "_script": {
                            "type": "number",
                            "script": {
                                "lang": "painless",
                                "source": "Math.random()"
                            },
                            "order": "asc"
                        }
                    }
                ]
            }
        },
        "_source": ["host"]
    }

    response = db.con.search(index=URLS_INDEX, body=query_body)
    results = response.get('hits', {}).get('hits', [])
    for result in results:
        print('    \033[35m{} \t {}\033[0m'.format(result['_score'], result['_source']['host']))
    if results:
        random.shuffle(results)
        return [{
            "url": r["inner_hits"]["least_visited_hit"]["hits"]["hits"][0]["_source"]["url"],
            "host": r["_source"]["host"]
        } for r in results]

    return []


def get_oldest_unvisited_urls_from_bucket(db, size=100):
    """Get the oldest unvisited URLs from a random bucket using created_at timestamp."""
    random_bucket = random.randint(0, ELASTICSEARCH_RANDOM_BUCKETS - 1)
    print(f'    Selected bucket: \033[33m{random_bucket}\033[0m')

    query_body = {
        "size": size,
        "query": {
            "bool": {
                "must": [
                    {"term": {"random_bucket": random_bucket}},
                    {
                        "bool": {
                            "should": [
                                {"term": {"visited": False}},
                                {"bool": {"must_not": {"exists": {"field": "visited"}}}}
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ]
            }
        },
        "sort": [
            {"created_at": {"order": "asc"}}
        ]
    }

    response = db.con.search(index=URLS_INDEX, body=query_body)
    hits = response.get('hits', {}).get('hits', [])
    if hits:
        for hit in hits:
            print(f'    \033[35m{hit["_source"]["url"]}\033[0m')
        random.shuffle(hits)  # Shuffle the list in-place
        return [{
            "url": hit["_source"]["url"],
            "host": hit["_source"]["host"]
        } for hit in hits]

    return []


def get_urls_by_random_bucket_and_host_prefix(db, size=100):
    """Get 1 unvisited URL per host from a random bucket where host starts with a random character."""
    random_bucket = random.randint(0, ELASTICSEARCH_RANDOM_BUCKETS - 1)
    print(f'    Selected bucket: \033[33m{random_bucket}\033[0m')
    prefix_char = random.choice(string.ascii_lowercase + string.digits)

    query_body = {
        "size": size,
        "query": {
            "bool": {
                "must": [
                    {"term": {"random_bucket": random_bucket}},
                    {"prefix": {"host": prefix_char}},
                    {
                        "bool": {
                            "should": [
                                {"term": {"visited": False}},
                                {"bool": {"must_not": {"exists": {"field": "visited"}}}}
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ]
            }
        },
        "collapse": {
            "field": "host",
            "inner_hits": {
                "name": "random_unvisited_url",
                "size": 1,
                "sort": [
                    {
                        "_script": {
                            "type": "number",
                            "script": {
                                "lang": "painless",
                                "source": "Math.random()"
                            },
                            "order": "asc"
                        }
                    }
                ]
            }
        },
        "_source": ["host"]
    }
    response = db.con.search(index=URLS_INDEX, body=query_body)
    results = response.get('hits', {}).get('hits', [])
    if results:
        urls = [{
            "url": r["inner_hits"]["random_unvisited_url"]["hits"]["hits"][0]["_source"]["url"],
            "host": r["_source"]["host"]
        } for r in results]
        for url in urls:
            print('    \033[35m{}\033[0m'.format(url['url']))
        random.shuffle(urls)
        return urls
    return []


def get_random_host_domains(db, size=100):
    random_bucket = random.randint(0, ELASTICSEARCH_RANDOM_BUCKETS - 1)
    print(f'    Selected bucket: \033[33m{random_bucket}\033[0m')
    query_body = {
        "size": size,
        "query": {
            "bool": {
                "must": [
                    {"term": {"random_bucket": random_bucket}}
                ],
                "should": [
                    {"term": {"visited": False}},
                    {"bool": {"must_not": {"exists": {"field": "visited"}}}}
                ],
                "minimum_should_match": 1
            }
        },
        "collapse": {
            "field": "host",
            "inner_hits": {
                "name": "random_hit",
                "size": 1,
                "sort": [
                    {
                        "_script": {
                            "type": "number",
                            "script": {
                                "lang": "painless",
                                "source": "Math.random()"
                            },
                            "order": "asc"
                        }
                    }
                ]
            }
        }
    }

    response = db.con.search(index=URLS_INDEX, body=query_body)
    results = response.get('hits', {}).get('hits', [])

    if results:
        random.shuffle(results)
        result = [{
            "url": r["inner_hits"]["random_hit"]["hits"]["hits"][0]["_source"]["url"],
            "host": r["_source"]["host"]
        } for r in results]
        for url in result:
            print('    \033[35m{}\033[0m'.format(url['url']))
        return result
    return []


def fast_extension_crawler(url, extension, content_type_patterns, db):
    headers = {"User-Agent": UserAgent().random}
    try:
        head_resp = requests.head(url, timeout=(10, 10), allow_redirects=True, verify=False, headers=headers)
    except Exception as e:
        db_insert_if_new_url(url=url, visited=True, words='', min_webcontent='', raw_webcontent='',
                             source='fast_extension_crawler.head.exception', db=db)
        return

    if not (200 <= head_resp.status_code < 300):
        return

    print('-{}-'.format(url))
    content_type = head_resp.headers.get("Content-Type", "").lower().split(";")[0].strip()

    content_type = head_resp.headers.get("Content-Type", "")
    if not content_type:
        print(f"[FAST CRAWLER] No content type found for {url}")
        mark_url_as_fast_crawled(url, db)
        return

    content_type = content_type.lower().split(";")[0].strip()
    if not any(re.match(pattern, content_type) for pattern in content_type_patterns):
        print(f"[FAST CRAWLER] Mismatch content type for {url}, got: {content_type}")
        mark_url_as_fast_crawled(url, db)
        return

    try:
        host = urlparse(url).hostname or ""
        if is_host_block_listed(host) or not is_host_allow_listed(host) or is_url_block_listed(url):
            return

        if HUNT_OPEN_DIRECTORIES:
            insert_directory_tree(url, db)

        found = False
        for regex, function in content_type_functions:
            if regex.search(content_type):
                found = True

                needs_download = (
                    (function.__name__ == "content_type_audios" and DOWNLOAD_AUDIOS) or
                    (function.__name__ == "content_type_compresseds" and DOWNLOAD_COMPRESSEDS) or
                    (function.__name__ == "content_type_databases" and DOWNLOAD_DATABASES) or
                    (function.__name__ == "content_type_docs" and DOWNLOAD_DOCS) or
                    (function.__name__ == "content_type_fonts" and DOWNLOAD_FONTS) or
                    (function.__name__ == "content_type_images" and DOWNLOAD_NSFW) or
                    (function.__name__ == "content_type_images" and DOWNLOAD_SFW) or
                    (function.__name__ == "content_type_images" and DOWNLOAD_ALL_IMAGES) or
                    (function.__name__ == "content_type_midis" and DOWNLOAD_MIDIS) or
                    (function.__name__ == "content_type_pdfs" and DOWNLOAD_PDFS) or
                    (function.__name__ == "content_type_torrents" and DOWNLOAD_TORRENTS)
                )

                content = None
                if needs_download:
                    try:
                        get_resp = requests.get(url, timeout=(10, 30), stream=True, allow_redirects=True, verify=False, headers=headers)
                        content = get_resp.content
                    except Exception as e:
                        print(f"[FAST CRAWLER] Failed GET for {url}: {e}")
                        return

                function({
                    'url': url,
                    'visited': True,
                    'content_type': content_type,
                    'content': content,
                    'source': 'fast_extension_crawler',
                    'words': '',
                    'parent_host': '',
                    'db': db
                })
                break

        if not found:
            print(f"[FAST CRAWLER] UNKNOWN type -{url}- -{content_type}-")

    except Exception as e:
        print(f"[FAST CRAWLER] Error processing {url}: {e}")
    time.sleep(random.uniform(FAST_RANDOM_MIN_WAIT, FAST_RANDOM_MAX_WAIT))


def run_fast_extension_pass(db, max_workers=MAX_FAST_WORKERS):
    shuffled_extensions = list(EXTENSION_MAP.items())
    random.shuffle(shuffled_extensions)

    for extension, content_type_patterns in shuffled_extensions:
        buckets = list(range(ELASTICSEARCH_RANDOM_BUCKETS))
        random.shuffle(buckets)

        for random_bucket in buckets:
            print(f"[FAST CRAWLER] Extension: {extension} | Bucket: \033[33m{random_bucket}\033[0m")

            query = {
                "bool": {
                    "must": [
                        {"term": {"visited": False}},
                        {"wildcard": {"url": f"*{extension}"}},
                        {"term": {"random_bucket": random_bucket}}
                    ],
                    "must_not": [
                        {"term": {"fast_crawled": True}}
                    ]
                }
            }
            try:
                result = db.es.search(index=URLS_INDEX, query=query, size=10000)
                urls = result.get("hits", {}).get("hits", [])

                if not urls:
                    continue

                random.shuffle(urls)

                # Prepare (url, extension) tuples
                urls_with_extensions = [
                    (hit["_source"]["url"], extension)
                    for hit in urls
                ]

                # Run fast crawlers concurrently
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = [
                        executor.submit(fast_extension_crawler, url, extension, content_type_patterns, db)
                        for url, extension in urls_with_extensions
                    ]
                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception as e:
                            print(f"[FAST CRAWLER] Exception during execution: {e}")

            except Exception as e:
                print(f"[FAST CRAWLER] Error retrieving URLs for extension {extension} in bucket {random_bucket}: {e}")


def remove_invalid_urls(db):
    """
    Deletes documents from Elasticsearch where the 'url' field is invalid
    or missing a scheme. Re-inserts sanitized URLs if they change.
    """
    deleted = 0
    query = {"query": {"match_all": {}}}

    for doc in helpers.scan(db.es, index=URLS_INDEX, query=query):
        url = doc['_source'].get('url')
        if not url:
            continue

        parsed = urlparse(url)
        pre_url = url
        url = sanitize_url(url)

        # Remove if URL changed after sanitization
        if pre_url != url:
            print(f"Deleted sanitized URL: -{pre_url}- inserting -{url}-")
            db_insert_if_new_url(url=url, visited=False, source="remove_invalid_urls", db=db)
            db.es.delete(index=URLS_INDEX, id=doc['_id'])
            deleted += 1
            continue

        # Remove if completely missing a scheme (e.g., "www.example.com")
        if not parsed.scheme:
            print(f"Deleted URL with no scheme: -{url}-")
            db.es.delete(index=URLS_INDEX, id=doc['_id'])
            deleted += 1

    print(f"\nDone. Total invalid URLs deleted: {deleted}")


def remove_blocked_hosts_from_es_db(db):
    compiled_blocklist = [re.compile(pattern) for pattern in HOST_REGEX_BLOCK_LIST]

    def is_blocked(host):
        return any(regex.search(host) for regex in compiled_blocklist)
    deleted = 0
    query = {"query": {"match_all": {}}}
    try:
        for doc in helpers.scan(db.es, index=URLS_INDEX, query=query):
            url = doc['_source'].get('url')
            if not url:
                continue
            host = urlsplit(url).hostname or ''
            if is_blocked(host):
                db.es.delete(index=URLS_INDEX, id=doc['_id'])
                print(f"Deleted: {url}")
                deleted += 1
    except NotFoundError as e:
        if "index_not_found_exception" in str(e):
            print("Elasticsearch index missing. Creating now...")
            db_create_database(INITIAL_URL, db=db)
    print(f"\nDone. Total deleted: {deleted}")


def remove_blocked_urls_from_es_db(db):
    # Compile path-based regex block list
    compiled_url_blocklist = [re.compile(pattern) for pattern in URL_REGEX_BLOCK_LIST]

    def is_blocked_path(path):
        return any(regex.search(path) for regex in compiled_url_blocklist)

    deleted = 0
    query = {"query": {"match_all": {}}}
    try:
        for doc in helpers.scan(db.es, index=URLS_INDEX, query=query):
            url = doc['_source'].get('url')
            if not url:
                continue
            path = urlsplit(url).path or ''
            if is_blocked_path(path):
                db.es.delete(index=URLS_INDEX, id=doc['_id'])
                print(f"Deleted by path: {url}")
                deleted += 1
    except NotFoundError as e:
        if "index_not_found_exception" in str(e):
            print("Elasticsearch index missing. Creating now...")
            db_create_database(INITIAL_URL, db=db)
    print(f"\nDone. Total deleted by path: {deleted}")


def make_https_app():
    return web.Application([
        (r"/(.*)", web.StaticFileHandler, {
            "path": os.getcwd(),
            "default_filename": "index.html"
        })
    ], debug=False)


def start_https_server():
    # Generate self-signed cert (only if not exists)
    if not (os.path.exists("cert.pem") and os.path.exists("key.pem")):
        os.system("openssl req -nodes -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -subj '/CN=mylocalhost'")

    app = make_https_app()
    server = httpserver.HTTPServer(app, ssl_options={
        "certfile": "cert.pem",
        "keyfile": "key.pem",
    })
    server.listen(EMBED_PORT)
    print(f"Serving HTTPS at https://localhost:{EMBED_PORT}")

    # Run the server in the background using Tornado's IOLoop
    ioloop.IOLoop.current().spawn_callback(lambda: None)  # ensure IOLoop starts
    ioloop.IOLoop.current().start()


def get_instance_number():
    """
    Uses file locking to detect which instance this is.
    Returns 1 for the first, 2 for the second, 3+ for others.
    Keeps the lock file open to avoid lock release.
    """
    global lock_file
    try:
        os.makedirs("/tmp/instance_flags", exist_ok=True)
        for i in range(1, 100):
            lock_path = f"/tmp/instance_flags/instance_{i}.lock"
            lock_file = open(lock_path, "w")  # keep open!
            try:
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return i
            except BlockingIOError:
                lock_file.close()
                continue
    except Exception as e:
        print(f"Error determining instance number: {e}")
    return 999


def process_input_url_files(db):
    if not os.path.isdir(INPUT_DIR):
        return

    while True:
        files = [f for f in os.listdir(INPUT_DIR) if os.path.isfile(os.path.join(INPUT_DIR, f))]
        if not files:
            print("No more input files to process.")
            break

        file_to_process = os.path.join(INPUT_DIR, random.choice(files))
        print(f"Processing input file: {file_to_process}")

        with open(file_to_process, "r", encoding="utf-8") as f:
            lines = f.readlines()

        if not lines:
            print(f"File is empty, deleting: {file_to_process}")
            os.remove(file_to_process)
            continue

        urls_to_process = lines[:MAX_URLS_FROM_FILE]
        remaining = lines[MAX_URLS_FROM_FILE:]

        driver = initialize_driver()
        for url in urls_to_process:
            url = url.strip()
            if not url:
                continue
            try:
                print('    [FILE] {}'.format(url))
                del driver.requests
                get_page(url, driver, db)
                if HUNT_OPEN_DIRECTORIES:
                    insert_directory_tree(url, db)
            except Exception as e:
                print(f"Error crawling {url}: {e}")
        driver.quit()

        # Rewrite file with remaining lines
        if remaining:
            with open(file_to_process, "w", encoding="utf-8") as f:
                f.writelines(remaining)
        else:
            os.remove(file_to_process)
            print(f"File fully processed and removed: {file_to_process}")


def main():
    instance = get_instance_number()
    db = DatabaseConnection()
    if instance == 1:
        print("Instance 1: Running HTTPS webserver to embed http site for compatibility with selenium-wire.")
        # Run HTTPS in a background thread to avoid blocking the crawler
        import threading
        threading.Thread(target=start_https_server, daemon=True).start()
        time.sleep(1)  # Give HTTPS server a head start
        if REMOVE_BLOCKED_HOSTS:
            print("Instance 1: Removing urls from hosts that are blocklisted.")
            remove_blocked_hosts_from_es_db(db)
        if REMOVE_BLOCKED_URLS:
            print("Instance 1: Removing path blocklisted urls.")
            remove_blocked_urls_from_es_db(db)
        if REMOVE_INVALID_URLS:
            print("Instance 1: Deleting invalid urls.")
            remove_invalid_urls(db)
        print("Instance 1: Checking for input URL files...")
        process_input_url_files(db)
        print("Instance 1: Let's go full crawler mode.")
        crawler(db)
    elif instance == 2:
        print("Instance 2: Running fast extension pass only. Not everything needs selenium... running requests in urls that looks like files.")
        run_fast_extension_pass(db)
    elif instance == 3:
        print("Instance 3: Scanning IPs in some unconventional ports and protocols combinations.")
        try:
            subprocess.run(["venv/bin/python3", "scanner.py"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error while running scanner.py: {e}")
    else:
        print(f"Instance {instance}: Running full crawler.")
        crawler(db)
    db.close()


if __name__ == "__main__":
    main()

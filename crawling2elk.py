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


# Verify if host is in a blocklist.
def is_host_block_listed(url):
    for regex in HOST_REGEX_BLOCK_LIST:
        if re.search(regex, url, flags=re.I | re.U):
            return True
    return False


# Verify if url is in a blocklist.
def is_url_block_listed(url):
    for regex in URL_REGEX_BLOCK_LIST:
        if re.search(regex, url, flags=re.I | re.U):
            return True
    return False


# Verify if url is in a allowlist.
def is_host_allow_listed(url):
    for regex in HOST_REGEX_ALLOW_LIST:
        if re.search(regex, url, flags=re.I | re.U):
            return True
    return False


def build_conditional_update_script(doc: dict) -> tuple[str, dict]:
    script_lines = []
    params = {}

    for key, value in doc.items():
        params[key] = value

        if key == "visited":
            script_lines.append(
                "if (ctx._source.visited == null || "
                "ctx._source.visited == false) {\n"
                "    ctx._source.visited = params.visited;\n"
                "}"
            )
        elif key != "updated_at":
            script_lines.append(
                f"if (ctx._source['{key}'] != params['{key}']) {{\n"
                f"    ctx._source['{key}'] = params['{key}'];\n"
                f"}}"
            )

    # Only update updated_at if any other field changed
    script_lines.append(
        "if (ctx._source != params.existing_source_snapshot) {\n"
        "    ctx._source.updated_at = params.updated_at;\n"
        "}"
    )

    return "\n".join(script_lines), params


def get_words(text: bytes | str) -> list[str]:
    if not text:
        return []
    if isinstance(text, bytes):
        try:
            text = text.decode('utf-8', errors='replace')
        except Exception:
            return []
    return extract_top_words_from_text(text)


def get_words_from_soup(soup) -> list[str]:
    text_parts = [
        t for t in soup.find_all(string=True)
        if t.parent.name not in soup_tag_blocklist
    ]
    combined_text = " ".join(text_parts)
    return extract_top_words_from_text(combined_text)


def get_min_webcontent(soup):
    text_parts = [
        t for t in soup.find_all(string=True)
        if t.parent.name not in soup_tag_blocklist
    ]
    combined_text = " ".join(text_parts)
    return combined_text


def extract_top_words_from_text(text: str) -> list[str]:
    if WORDS_REMOVE_SPECIAL_CHARS:
        text = re.sub(r'[^\w\s]', ' ', text, flags=re.UNICODE)
    if WORDS_TO_LOWER:
        text = text.lower()

    words = [word for word in text.split() if
             WORDS_MIN_LEN < len(word) <= WORDS_MAX_LEN]
    most_common = Counter(words).most_common(WORDS_MAX_WORDS)
    return [word for word, _ in most_common]


def is_open_directory(content, content_url):
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
    ]

    for pat in patterns:
        if re.search(pat, content, re.IGNORECASE):
            print(f'### Is open directory - {content_url} - matched pattern: {pat}')
            return True
    return False


def function_for_url(regexp_list):
    def get_url_function(f):
        for regexp in regexp_list:
            url_functions.append((re.compile(regexp, flags=re.I | re.U), f))
        return f
    return get_url_function


# url unsafe {}|\^~[]`
# regex no need to escape '!', '"', '%', "'", ',', '/', ':', ';', '<', '=', '>', '@', and "`"
@function_for_url(
    [
        r"^(\/|\.\.\/|\.\/)",
        r"^[0-9\-\./\?=_\&\s%@<>\(\);\+!,\w\$\'–’—”“a°§£Ã¬´c�í¦a]+$",
        r"^[0-9\-\./\?=_\&\s%@<>\(\);\+!,\w\$\'–’—”“a°§£Ã¬´c]*[\?\/][0-9\-\./\?=_\&\s%@<>\(\);\+!,\w\$\'–’—”“a°§£Ã¬:\"¶c´™*]+$",
    ]
)
def relative_url(args):
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
    return True


@function_for_url(url_all_others_regex)
def do_nothing_url(args):
    # Do nothing with these regex. They are kept here only as a guideline if you
    # want to write your own functions for them
    return True


@function_for_url([r"^https*://", r"^ftp://"])
def full_url(args):
    parent_host = urlsplit(args['parent_url'])[1]
    db_insert_if_new_url(url=args['url'], source="full_url", visited=False, parent_host=parent_host, db=args['db'])
    return True


@function_for_url(
    [
        r"^(mailto:|maillto:|maito:|mail:|malito:|mailton:|\"mailto:|emailto:|maltio:|mainto:|E\-mail:|mailtfo:|mailtp:|mailtop:|mailo:|mail to:|Email para:|email :|email:|E-mail: |mail-to:|maitlo:|mail.to:)"
    ]
)
def email_url(args):
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
    def get_content_type_function(f):
        for regexp in regexp_list:
            content_type_functions.append((re.compile(regexp, flags=re.I | re.U), f))
        return f
    return get_content_type_function


def get_directory_tree(url):
    # Host will have scheme, hostname and port
    host = '://'.join(urlsplit(url)[:2])
    dtree = []
    for iter in range(1, len(PurePosixPath(unquote(urlparse(url).path)).parts[0:])):
        dtree.append(str(host+'/'+'/'.join(PurePosixPath(unquote(urlparse(url).path)).parts[1:-iter])))
    return dtree


def insert_directory_tree(content_url, db):
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
    min_webcontent=''
    raw_webcontent=''
    if EXTRACT_WORDS:
        words = get_words_from_soup(soup)

    if EXTRACT_RAW_WEBCONTENT:
        raw_webcontent=str(soup)[:MAX_WEBCONTENT_SIZE]

    if EXTRACT_MIN_WEBCONTENT:
        min_webcontent=get_min_webcontent(soup)[:MAX_WEBCONTENT_SIZE]

    isopendir = is_open_directory(str(soup), args['url'])
    db_insert_if_new_url(url=args['url'],content_type=args['content_type'],isopendir=isopendir,visited=True,words=words,min_webcontent=min_webcontent,raw_webcontent=raw_webcontent,source='content_type_html_regex',parent_host=args['parent_host'],db=args['db'])
    return True


@function_for_content_type(content_type_plain_text_regex)
def content_type_plain_text(args):
    words = ''
    if EXTRACT_WORDS:
        words = get_words(args['content'])
    db_insert_if_new_url(url=args['url'],content_type=args['content_type'],isopendir=False,visited=True,words=words,source='content_type_plain_text_regex',parent_host=args['parent_host'],db=args['db'])
    return True


@function_for_content_type(content_type_image_regex)
def content_type_images(args):
    global model
    npixels=0
    if CATEGORIZE_NSFW or DOWNLOAD_ALL_IMAGES:
        try:
            img = Image.open(BytesIO(args['content']))
            width, height = img.size
            npixels = width * height
            nsfw_probability=0
            if img.mode == "CMYK":
                img = img.convert("RGB")
            # Check if it's a palette-based image with transparency
            if img.mode == "P" and "transparency" in img.info:
                # Convert to RGBA to handle transparency properly
                img = img.convert("RGBA")
            filename = hashlib.sha512(img.tobytes()).hexdigest() + ".png"
        except UnidentifiedImageError as e:
            #SVG using cairo in the future
            db_insert_if_new_url(url=args['url'], content_type=args['content_type'],source='content_type_images',isopendir=False, visited=True,parent_host=args['parent_host'],resolution=npixels,db=args['db'])
            return False
        except Image.DecompressionBombError as e:
            db_insert_if_new_url(url=args['url'], content_type=args['content_type'],source='content_type_images',isopendir=False, visited=True,parent_host=args['parent_host'],resolution=npixels,db=args['db'])
            return False
        except OSError:
            db_insert_if_new_url(url=args['url'], content_type=args['content_type'],source='content_type_images',isopendir=False, visited=True,parent_host=args['parent_host'],resolution=npixels,db=args['db'])
            return False
        if DOWNLOAD_ALL_IMAGES:
            img.save(IMAGES_FOLDER+'/' + filename, "PNG")
        if CATEGORIZE_NSFW and npixels > MIN_NSFW_RES :
            image = n2.preprocess_image(img, n2.Preprocessing.YAHOO)
            inputs = np.expand_dims(image, axis=0) 
            predictions = model.predict(inputs, verbose=0)
            sfw_probability, nsfw_probability = predictions[0]
            db_insert_if_new_url(args['url'],content_type=args['content_type'],source='content_type_images',visited=True,parent_host=args['parent_host'],isnsfw=nsfw_probability,isopendir=False,resolution=npixels, db=args['db'])
            if nsfw_probability>NSFW_MIN_PROBABILITY:
                print('porn {} {}'.format(nsfw_probability,args['url']))
                if DOWNLOAD_NSFW:
                    img.save(NSFW_FOLDER +'/'+ filename, "PNG")
            else:
                if DOWNLOAD_SFW:
                    img.save(SFW_FOLDER +'/' +filename, "PNG")
    db_insert_if_new_url(url=args['url'], content_type=args['content_type'],source='content_type_images',isopendir=False, visited=True,parent_host=args['parent_host'],resolution=npixels,db=args['db'])
    return True


@function_for_content_type(content_type_midi_regex)
def content_type_midis(args):
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


@function_for_content_type(content_type_font_regex)
def content_type_fonts(args):
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
    # We update as visited.
    db_insert_if_new_url(url=args['url'],visited=True,isopendir=False,content_type=args['content_type'],source='content_type_all_others_regex',parent_host=args['parent_host'],db=args['db'])
    return True


def sanitize_content_type(content_type):
    content_type = content_type.strip() 
    content_type = content_type.rstrip()      
    content_type = re.sub(r'^"(.*)"$', r"\1", content_type) # remove surrounding quotes if present
    content_type = re.sub(r'^content-type: (.*)"$', r"\1", content_type) # remove "content-type:" prefix
    content_type = re.sub(r'^content-type:(.*)"$', r"\1", content_type) # remove "content-type:" prefix  
    content_type = re.sub(r'^(.*?);.*$', r"\1",content_type) # keep only the type/subtype part
    content_type = re.sub(r'\s+', '', content_type)  # remove any remaining spaces
    return content_type


def get_page(url, driver, db):
    original_url=url
    driver = read_web(url, driver)  # Fetch the page using Selenium
    parent_host = urlsplit(url)[1]  # Get the parent host from the URL
    if driver:
        for request in driver.requests:
            if request.response:
                # Check if the response status code indicates redirection
                status_code = request.response.status_code
                if status_code in [301, 302, 303, 307, 308]:  # Redirection status codes
                    # Get the new URL from the Location header
                    db_insert_if_new_url(url=url,visited=True,isopendir=False,source='get_page.redirect',parent_host=parent_host,db=db)
                # Continue with normal content processing 
                if 'Content-Type' in request.response.headers:
                    url=request.url
                    host=urlsplit(url)[1]

                    try: 
                        content = decode(request.response.body, request.response.headers.get('Content-Encoding', 'identity'))
                    except ValueError as e:  # 🛠️ Catch specific Brotli decompression failure
                        if "BrotliDecompress failed" in str(e):
                            db_insert_if_new_url(url=url,visited=True,source='BrotliDecompressFailed',parent_host=parent_host,db=db)
                            continue
                        elif "LookupError when decoding" in str(e):
                            db_insert_if_new_url(url=url,visited=True,source='lookuperror',parent_host=parent_host,db=db)
                            continue
                        elif "EOFError when decoding" in str(e):
                            db_insert_if_new_url(url=url,visited=True,source='EOFERROR',parent_host=parent_host,db=db)
                            continue
                        elif "BadGzipFile when decoding" in str(e):
                            db_insert_if_new_url(url=url,visited=True,source='BadGzipFile',parent_host=parent_host,db=db)
                            continue
                        elif "UnicodeDecodeError when decoding" in str(e):
                            db_insert_if_new_url(url=url,visited=True,source='UnicodeDecodeError',parent_host=parent_host,db=db)
                            continue
                        else:
                            print(f"\033[91m🚨 !!!! This was not updated in the database, you need to deal with this error in the code function get_page [DECODE ERROR] {url} - {e} -\033[0m")
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
                                function({'url': url, 'visited': True, 'content_type': content_type, 
                                          'content': content, 'source': 'get_page', 'words': '', 
                                          'parent_host': parent_host, 'db': db})
                        if not found:
                            print(f"UNKNOWN type -{url}- -{content_type}-")
        #force update on main url
        db_insert_if_new_url(url=url,visited=True,source='get_page.end',parent_host=parent_host,db=db)
    #force update on main url
    db_insert_if_new_url(url=original_url,visited=True,source='get_page.end.original',parent_host=parent_host,db=db)


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
    prefs = {"download.default_directory": DIRECT_LINK_DOWNLOAD_FOLDER,}
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
    #options.add_argument('--disable-webrtc')
    #options.add_argument('--disable-geolocation')
    #options.add_argument('--disable-infobars')
    #options.add_argument('--disable-popup-blocking')
    #options.add_argument('--disable-javascript')
    #options.add_argument('--proxy-server=http://your-proxy-server:port')
    #options.add_argument('--proxy-server=http://'+PROXY_HOST+':'PROXY_PORT)

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
                    get_page(target_url['url'], driver,db)
                    if HUNT_OPEN_DIRECTORIES:
                        insert_directory_tree(target_url['url'],db)
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
        method_weights=METHOD_WEIGHTS

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
    s=search(search_for, num_results=100, unique=True, safe=None)
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
    for attempt in range(MAX_ES_RETRIES):
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
            print('    \033[35m{}\t-{}-\033[0m'.format(bucket['doc_count'],bucket['key']))

        if not hosts:
            continue

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
    for attempt in range(MAX_ES_RETRIES):
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
            print('    \033[35m{} \t {}\033[0m'.format(result['_score'],result['_source']['host']))
        if results:
            random.shuffle(results)
            return [{
                "url": r["inner_hits"]["least_visited_hit"]["hits"]["hits"][0]["_source"]["url"],
                "host": r["_source"]["host"]
            } for r in results]

    return []


def get_oldest_unvisited_urls_from_bucket(db, size=100):
    """Get the oldest unvisited URLs from a random bucket using created_at timestamp."""
    for attempt in range(MAX_ES_RETRIES):
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
                { "created_at": { "order": "asc" } }
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
    for attempt in range(MAX_ES_RETRIES):
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
    for attempt in range(MAX_ES_RETRIES):
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
                    (function.__name__ == "content_type_docs" and DOWNLOAD_DOCS) or
                    (function.__name__ == "content_type_fonts" and DOWNLOAD_FONTS) or
                    (function.__name__ == "content_type_torrents" and DOWNLOAD_TORRENTS) or
                    (function.__name__ == "content_type_pdfs" and DOWNLOAD_PDFS) or
                    (function.__name__ == "content_type_compresseds" and DOWNLOAD_COMPRESSEDS) or
                    (function.__name__ == "content_type_audios" and DOWNLOAD_AUDIOS) or
                    (function.__name__ == "content_type_midis" and DOWNLOAD_MIDIS) or
                    (function.__name__ == "content_type_images" and DOWNLOAD_NSFW) or 
                    (function.__name__ == "content_type_images" and DOWNLOAD_SFW) or 
                    (function.__name__ == "content_type_images" and DOWNLOAD_ALL_IMAGES)
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
    time.sleep(random.uniform(FAST_RANDOM_MIN_WAIT,FAST_RANDOM_MAX_WAIT))


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
        print("Instance 1: Removing urls from hosts that are blocklisted.")
        remove_blocked_hosts_from_es_db(db)
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

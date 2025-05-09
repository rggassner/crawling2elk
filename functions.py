import random, hashlib, time, re, string, json
import os
from config import *
from urllib.parse import urlsplit, urlunsplit, unquote, parse_qs
from datetime import datetime, timezone
from elasticsearch import NotFoundError, RequestError
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError, RequestError
from elasticsearch import ConflictError

class DatabaseConnection:
    def __init__(self):
        es_config = {
            "hosts": [f"https://{ELASTICSEARCH_HOST}:{ELASTICSEARCH_PORT}"],
            "basic_auth": (ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD),
            "verify_certs": False,
        }
        if ELASTICSEARCH_CA_CERT_PATH:
            es_config["ca_certs"] = ELASTICSEARCH_CA_CERT_PATH

        self.es = Elasticsearch(**es_config)
        self.con = self.es  # ✅ Optional alias for compatibility

    def commit(self):
        pass

    def close(self):
        self.es.close()

    def search(self, *args, **kwargs):
        return self.es.search(*args, **kwargs)

    def scroll(self, *args, **kwargs):
        return self.es.scroll(*args, **kwargs)

def sanitize_url(url, debug=True, skip_log_tags=['FINAL_NORMALIZE','STRIP_WHITESPACE','NORMALIZE_PATH_SLASHES']):
    """
    Sanitize URLs by removing quotes, fixing common typos, and normalizing format.
    """
    if skip_log_tags is None:
        skip_log_tags = set()

    def log_change(reason, before, after):
        if before != after and reason not in skip_log_tags and debug:
            print(f"\033[91m[{reason}] URL sanitized from -{before}- to -{after}-\033[00m")

    def clean_hostname_with_userinfo(netloc, scheme):
        """
        Cleans netloc, preserving valid username:password@host:port patterns.
        Removes invalid characters, strips default ports, and validates port range.
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
                if (scheme == 'http' and port == '80') or (scheme == 'https' and port == '443'):
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

    #if applied to full url it removes more than it should. Evaluate in the future for hostname, port or schema
    #quote_patterns = [
    #    r'^"([^"]*)"$',
    #    r"^'([^']*)'",
    #    r'^"([^"]*)',
    #    r"^'([^']*)'$"
    #]
    #for pattern in quote_patterns:
    #    cleaned = re.sub(pattern, r'\1', url)
    #    log_change("QUOTE_CLEAN", url, cleaned)
    #    url = cleaned

    for pattern, replacement in special_quote_pairs:
        cleaned = re.sub(pattern, replacement, url)
        log_change("SPECIAL_QUOTE_CLEAN", url, cleaned)
        url = cleaned

    scheme_fixes = [
        (r'^ps://', 'https://'), (r'^ttps://', 'https://'),
        (r'^htpps://', 'https://'), (r'^httpp://', 'https://'), (r'^http:s//', 'https://'),
        (r'^hthttps://', 'https://'), (r'^httsp://', 'https://'), (r'^htts://', 'https://'),
        (r'^htttps://', 'https://'), (r'^https:https://', 'https://'), (r'^https https://', 'https://'),
        (r'^httpshttps://', 'https://'), (r'^https://https://', 'https://'), (r'^"https://', 'https://'),
        (r'^httpd://', 'https://'), (r'^htps://', 'https://'), (r'^https: //', 'https://'),
        (r'^https : //', 'https://'), (r'^http2://', 'https://'), (r'^https%3A//', 'https://'),
        (r'^%20https://', 'https://'), (r'^htto://', 'http://'), (r'^htt://', 'http://'),
        (r'^htp://http//', 'http://'), (r'^htp://', 'http://'), (r'^hhttp://', 'http://'),
        (r'^http:/http://', 'http://'), (r'^http:www', 'http://www'), (r'^htttp://', 'http://'),
        (r'^ttp://', 'http://'), (r'^%20http://', 'http://'), (r'^%22mailto:', 'mailto:'),
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
                rebuilt = urlunsplit((scheme, netloc, path, parsed.query, parsed.fragment))
                log_change("FIX_NETLOC_IN_PATH", url, rebuilt)
                url = rebuilt
        else:
            path = re.sub(r'/{2,}', '/', parsed.path)
            rebuilt = urlunsplit((scheme, netloc, path, parsed.query, parsed.fragment))
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
            if (scheme == 'http' and port == '80') or (scheme == 'https' and port == '443'):
                netloc = host

        path = safe_normalize_path_slashes(parsed.path)
        normalized = urlunsplit((scheme, netloc, path, parsed.query, ''))
        log_change("FINAL_NORMALIZE", url, normalized)
        return normalized.strip()
    except Exception:
        return url.strip()

def hash_url(url):
    return hashlib.sha256(url.encode('utf-8')).hexdigest()

def remove_jsessionid_with_semicolon(url):
    pattern = r';jsessionid=[^&?]*'
    cleaned_url = re.sub(pattern, '', url)
    return cleaned_url

def db_insert_if_new_url(url='', isopendir=None, visited=None, source='', content_type='', words='', min_webcontent='', raw_webcontent='',
                         isnsfw='', resolution='', parent_host='', email=None, db=None, debug=False):

    if debug:
        print(f"[DEBUG] visited param type: {type(visited)} - value: {visited}")

    host = urlsplit(url)[1]
    url = remove_jsessionid_with_semicolon(url)
    url = sanitize_url(url)
    parsed = urlsplit(url)
    query = parsed.query
    has_query = bool(query)
    query_dict = parse_qs(query)

    query_variables = list(set(query_dict.keys()))
    query_values = list(set(v for values in query_dict.values() for v in values))

    now_iso = datetime.now(timezone.utc).isoformat()
    doc_id = hash_url(url)

    try:
        existing_doc = None
        if debug:
            try:
                existing_doc = db.con.get(index=URLS_INDEX, id=doc_id)["_source"]
            except Exception:
                print(f"[DEBUG] Could not fetch existing doc for {url}: {get_err}")


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
            insert_only_fields["random_bucket"] = random.randint(0, ELASTICSEARCH_RANDOM_BUCKETS - 1)

            if source:
                insert_only_fields["source"] = source
            if parent_host:
                insert_only_fields["parent_host"] = parent_host

            # Safely extract host and directory levels
            host_parts = get_host_levels(host).get("host_levels", [])
            if len(host_parts) < MAX_HOST_LEVELS:
                host_parts = [''] * (MAX_HOST_LEVELS - len(host_parts)) + host_parts

            dir_parts = get_directory_levels(urlsplit(url).path).get("directory_levels", [])
            if len(dir_parts) < MAX_DIR_LEVELS:
                dir_parts = [''] * (MAX_DIR_LEVELS - len(dir_parts)) + dir_parts

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
            file_extension = file_extension.lower().lstrip('.') if file_extension else ''

            if file_extension:
                insert_only_fields['file_extension'] = file_extension

            for i, part in enumerate(reversed(host_parts[-MAX_HOST_LEVELS:])):
                insert_only_fields[f"host_level_{i+1}"] = part

            for i, part in enumerate(dir_parts[:MAX_DIR_LEVELS]):
                insert_only_fields[f"directory_level_{i+1}"] = part

        # Fields that may be updated
        doc = {}
        if content_type: doc["content_type"] = content_type
        if words: doc["words"] = words
        if min_webcontent: doc["min_webcontent"] = min_webcontent
        if raw_webcontent: doc["raw_webcontent"] = raw_webcontent
        if isopendir is not None:
            doc["isopendir"] = bool(isopendir)
        if isnsfw: doc["isnsfw"] = float(isnsfw)
        if resolution:
            doc["resolution"] = int(resolution) if str(resolution).isdigit() else 0
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
                        print(f"[DEBUG] INSERT - Comparing update for URL: {url}")
                        print(f"  🔄 {key}: '{old_value}' ➡ '{new_value}'")
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
                script_lines.append("""
                    if (!ctx._source.containsKey('visited') || ctx._source.visited == false) {
                        ctx._source.visited = params.visited;
                        has_updated = true;
                    }
                """)
            else:
                script_lines.append(f"""
                    if (params.containsKey('{key}')) {{
                        def old_val = ctx._source.containsKey('{key}') ? ctx._source['{key}'] : null;
                        if (old_val != params['{key}']) {{
                            ctx._source['{key}'] = params['{key}'];
                            has_updated = true;
                        }}
                    }}
                """)

        script_lines.append("if (has_updated) { ctx._source.updated_at = params.updated_at; }")
        script = "\n".join(script_lines)

        # Merge doc fields safely
        try:
            upsert_doc = {**insert_only_fields, **doc}
        except Exception as merge_err:
            print("[DEBUG] 🔥 Error merging insert_only_fields and doc")
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
                return True  # ✅ Success on first or second attempt
            except ConflictError as ce:
                if attempt == 0:
                    if debug:
                        print(f"[RETRY] 🔁 Version conflict on first attempt for URL: {url}")
                    time.sleep(0.05)  # Slight pause before retry
                else:
                    print(f"[Elasticsearch] ❌ Final ConflictError on retry for URL '{url}': {ce}")
                    return False
            except Exception as e:
                print(f"[Elasticsearch] ❌ Error inserting URL '{url}': {type(e).__name__} - {e}")
                return False


    except Exception as e:
        print(f"[Elasticsearch] ❌ Error inserting URL '{url}': {type(e).__name__} - {e}")
        return False

def get_host_levels(hostname):
    """Returns all host levels from right (TLD) to left (subdomain), ignoring any port number."""
    hostname = hostname.split(':')[0]  # Remove port if present
    parts = hostname.split('.')
    parts_reversed = list(parts)
    return {
        "host_levels": parts_reversed,
        "host_level_map": {f"host_level_{i+1}": level for i, level in enumerate(parts_reversed)}
    }


def get_directory_levels(url_path):
    """Extracts all directory levels from a URL path and ensures correct numbering."""
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


content_type_html_regex=[
        r"^text/html$",
        r"^text/html,text/html",
        r"^text/fragment\+html$",
        r"^text/html, charset=.*",
        r"^application/html$",
        r"^application/xhtml\+xml$",
        r"^text/x-html-fragment$",
        r"^text/vnd\.reddit\.partial\+html$",
    ]

content_type_midi_regex=[
        r"^audio/midi$",
        r"^audio/sp-midi$",
    ]

content_type_audio_regex=[
        r"^audio/ogg$",
        r"^audio/mp3$",
        r"^audio/mp4$",
        r"^audio/wav$",
        r"^audio/MP2T$",
        r"^audio/flac$",
        r"^audio/mpeg$",
        r"^audio/opus$",
        r"^audio/x-rpm$",
        r"^audio/x-wav$",
        r"^audio/x-flac$",
        r"^audio/unknown$",
        r"^audio/mpegurl$",
        r"^audio/x-scpls$",
        r"^audio/x-ms-wma$",
        r"^application/mp3$",
        r"^audio/x-mpegurl$",
        r"^audio/x-pn-realaudio$",
        r"^application/vnd\.rn-realmedia$",
    ]

content_type_compressed_regex =[
        r"^multipart/x-zip$",
        r"^application/zip$",
        r"^application/rar$",
        r"^application/gzip$",
        r"^application/x-xz$",
        r"^application/\.rar$",
        r"^application/\.zip$",
        r"^application/x-zip$",
        r"^application/x-rar$",
        r"^application/x-tar$",
        r"^application/x-gzip$",
        r"^application/x-bzip2$",
        r"^application/x-tar-gz$",
        r"^application/x-compress$",
        r"^application/x-7z-compressed$",
        r"^application/x-rar-compressed$",
        r"^application/x-zip-compressed$",
        r"^application/x-gtar-compressed$",
        r"^application/x-zip-compressedcontent-length:",
        r"^application/vnd\.adobe\.air-application-installer-package\+zip$",
    ]

content_type_pdf_regex = [
        r"^adobe/pdf$",
        r"^application/pdf$",
        r"^application/\.pdf$",
        r"^application/pdfcontent-length:",
    ]

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
        r"^image/gif$",
        r"^image/png$",
        r"^image/bmp$",
        r"^image/svg$",    
        r"^image/jpg$",
        r"^image/any$",
        r"^image/apng$",
        r"^image/avif$",    
        r"^image/jpeg$",
        r"^image/tiff$",
        r"^image/webp$",
        r"^image/pjpeg$",
        r"^image/x-png$",
        r"^image/x-eps$",
        r"^image/dicomp$", 
        r"^image/x-icon$",
        r"^image/\{png\}$", 
        r"^data:image/png$",
        r"^image/vnd\.dwg$",    
        r"^image/svg\+xml$",
        r"^image/x-ms-bmp$",        
        r"^image/x-xbitmap$",        
        r"^image/x-photoshop$",         
        r"^image/x-coreldraw$",        
        r"^image/vnd\.wap\.wbmp$",
        r"^image/x\.fb\.keyframes$",        
        r"^image/vnd\.microsoft\.icon$",
        r"^application/jpg$",        
    ]

content_type_doc_regex = [
        r"^application/vnd\.openxmlformats-officedocument\.wordprocessingml\.document$",
        r"^application/vnd\.openxmlformats-officedocument\.wordprocessingml\.template$",
        r"^application/docx$",
        r"^application/doc$",
        r"^application/vnd\.ms-word\.document\.12$",
        r"^application/vnd\.oasis\.opendocument\.text$",
        ]

content_type_video_regex = [
        r"^video/mp4$",
        r"^video/ogg$",
        r"^video/f4v$",
        r"^video/m2ts$",
        r"^video/webm$",
        r"^video/MP2T$",
        r"^video/mpeg$",
        r"^video/x-m4v$",
        r"^video/x-flv$",
        r"^video/x-ms-wmv$",
        r"^video/x-ms-asf$",
        r"^application/ogg$",
        r"^application/wmv$",
        r"^application/avi$",
        r"^video/x-msvideo$",
        r"^video/quicktime$",
        r"^video/x-matroska$",
        r"^application/x-mpegurl$",
        r"^video/vnd\.dlna\.mpeg-tts$",
        r"^application/vnd\.apple\.mpegurl$",
        r"^application/vnd\.adobe\.flash\.movie$",
        ]

content_type_plain_text_regex = [
        r"^\.js$",
        r"^text/js$",
        r"^text/xml$",
        r"^text/srt$",
        r"^text/rtf$",
        r"^text/csv$",
        r"^text/vtt$",
        r"^app/json$",
        r"^text/x-sh$",
        r"^text/json$",
        r"^text/yaml$",
        r"^text/x-js$",
        r"^text/vcard$",
        r"^text/x-tex$",
        r"^text/plain$",
        r"^text/x-perl$",
        r"^text/x-chdr$",
        r"^text/x-json$",
        r"^text/turtle$",
        r"^text/x-vcard$",
        r"^text/calendar$",
        r"^text/x-ndjson$",
        r"^text/x-bibtex$",
        r"^text/uri-list$",
        r"^text/markdown$",
        r"^text/directory$",
        r"^text/x-vcalendar$",
        r"^text/x-component$",
        r"^application/text$",
        r"^application/jsonp$",
        r"^text/x-javascript$",
        r"^text/event-stream$",
        r"^application/ld\+json$",
        r"^application/ion\+json$",
        r"^application/hal\+json$",
        r"^application/stream\+json$",
        r"^application/problem\+json$",
        r"^text/0\.4/hammer\.min\.js$",
        r"^text/x-handlebars-template$",
        r"^application/vnd\.api\+json$",
        r"^application/x-thrift\+json$",
        r"^application/json\+protobuf$",
        r"^application/manifest\+json$",
        r"^application/importmap\+json$",
        r"^application/x-amz-json-1\.1$",
        r"^application/jsoncharset=UTF-8$",
        r"^text/x-comma-separated-values$",
        r"^application/speculationrules\+json$",
        r"^application/vnd\.vimeo\.user\+json$",
        r"^application/amazonui-streaming-json$",
        r"^application/vnd.inveniordm\.v1\+json$",
        r"^application/vnd\.maxmind\.com-city\+json$",
        r"^application/vnd\.maxmind\.com-error\+json$",
        r"^application/vnd\.radio-canada\.neuro\+json$",
        r"^application/vnd\.vimeo\.profilevideo\+json$",
        r"^application/vnd\.maxmind\.com-country\+json$",
        r"^application/vnd\.maxmind\.com-insights\+json$",
        r"^application/vnd\.vimeo\.profilesection\+json$",
        r"^application/vnd\.contentful\.delivery\.v1\+json$",
        r"^application/vnd\.spring-boot\.actuator\.v3\+json$",
    ]

url_all_others_regex =[
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
        r"^appstream:",
        r"^worldwind:",
        r"^x-webdoc:",
        r"^applenewss:",
        r"^itms-apps:",
        r"^itms-beta:",
        r"^santanderpf:",        
        r"^bitcoincash:",
        r"^android-app:",
        r"^ms-settings:",
        r"^applewebdata:",
        r"^fb-messenger:",
        r"^moz-extension:",
        r"^microsoft-edge:",
        r"^x-help-action:",
        r"^digitalassistant:",     
        r"^chrome-extension:",
        r"^ms-windows-store:",
        r"^(tel:|tellto:|te:|callto:|TT:|tell:|telto:|phone:|calto:|call:|telnr:|tek:|sip:|to:|SAC:|facetime-audio:|telefone:|telegram:|tel\+:|tal:|tele:|tels:|cal:|tel\.:)",
        r"^(javascript:|javacscript:|javacript:|javascripy:|javscript:|javascript\.|javascirpt:|javascript;|javascriot:|javascritp:|havascript:|javescript:|javascrip:|javascrpit:|js:|javascripr:|javastript:|javascipt:|javsacript:|javasript:|javascrit:|javascriptt:|ja vascript:|javascrtipt:|jasvascript:|javascropt:|jvascript:|javasctipt:|avascript:|javacsript:)",
    ]

content_type_all_others_regex = [
        r"^$",
        r"^-$",
        r"^\*$",
        r"^None$",
        r"^json$",
        r"^null$",
        r"^file$",
        r"^woff$",
        r"^\*/\*$",
        r"^woff2$",
        r"^unknown$",
        r"^font/ttf$",
        r"^font/otf$",
        r"^font/woff$",
        r"^font/woff2$",
        r"^\(null\)/woff2$",
        r"^font/truetype$",
        r"^x-font/ttf$",
        r"^font/sfnt$",
        r"^font/x-woff$",
        r"^x-font/woff$",
        r"^font/x-woff2$",
        r"^font/opentype$",
        r"^model/vnd\.mts$",
        r"^text/css$",
        r"^text/x-unknown-content-type$",
        r"^text/plaincharset:",
        r"^text/javascript$",
        r"^application/\*$",
        r"^application/xml$",
        r"^application/x-j$",
        r"^application/xls$",
        r"^application/jwt$",
        r"^application/rtf$",
        r"^application/csv$",
        r"^application/epub$",
        r"^application/node$",
        r"^application/xlsx$",
        r"^application/wasm$",
        r"^application/woff$",
        r"^application/mobi$",
        r"^application/save$",
        r"^application/null$",
        r"^application/zlib$",
        r"^application/json$",
        r"^application/x-sh$",
        r"^application/font$",
        r"^application/x-twb$",
        r"^application/x-msi$",
        r"^application/x-xar$",
        r"^application/x-ruby$",
        r"^application/x-frpc$",
        r"^application/x-tgif$",
        r"^application/x-perl$",
        r"^application/binary$",
        r"^application/msword$",
        r"^application/msword$",
        r"^application/x-doom$",
        r"^application/x-woff$",
        r"^application/x-trash$",
        r"^application/msexcel$",
        r"^application/x-woff2$",
        r"^application/unknown$",
        r"^application/xml-dtd$",
        r"^application/x-ndjson$",
        r"^application/x-adrift$",
        r"^application/x-binary$",
        r"^application/rdf\+xml$",
        r"^application/hr\+json$",
        r"^application/font-otf$",
        r"^application/download$",
        r"^application/rss\+xml$",
        r"^application/ms-excel$",
        r"^application/font-ttf$",
        r"^application/x-msword$",
        r"^application/pgp-keys$",
        r"^application/x-subrip$",
        r"^application/x-bibtex$",
        r"^application/pkix-crl$",
        r"^application/font-sfnt$",
        r"^application/ttml\+xml$",
        r"^application/xslt\+xml$",
        r"^application/dash\+xml$",
        r"^application/x-dosexec$",
        r"^application/epub\+zip$",
        r"^application/atom\+xml$",
        r"^application/x-msexcel$",
        r"^application/pkix-cert$",
        r"^application/font-woff$",
        r"^application/smil\+xml$",
        r"^application/x-director$",
        r"^application/postscript$",
        r"^application/x-font-ttf$",
        r"^application/x-font-otf$",
        r"^application/x-rss\+xml$",
        r"^application/font/woff2$",        
        r"^application/ecmascript$",
        r"^application/x-protobuf$",
        r"^application/pkcs7-mime$",
        r"^application/font-woff2$",
        r"^application/javascript$",
        r"^application/oct-stream$",
        r"^application/vnd\.yt-ump$",
        r"^application/octetstream$",
        r"^application/x-font-woff$",
        r"^application/x-xpinstall$",
        r"^application/x-httpd-php$",
        r"^application/x-directory$",
        r"^application/x-troff-man$",
        r"^application/x-bittorrent$",
        r"^application/java-archive$",
        r"^application/x-javascript$",
        r"^application/x-msdownload$",
        r"^application/x-font-woff2$",
        r"^application/octet-stream$",
        r"^application/vnd\.ms-word$",
        r"^application/x-executable$",
        r"^application/x-base64-frpc$",
        r"^application/pgp-signature$",
        r"^application/x-ms-manifest$",
        r"^application/x-mobi8-ebook$",
        r"^application/grpc-web-text$",
        r"^application/vnd\.ms-excel$",
        r"^application/force-download$",
        r"^x-application/octet-stream$",
        r"^application/x-x509-ca-cert$",
        r"^application/grpc-web\+proto$",
        r"^application/x-amz-json-1\.0$",
        r"^application/x-msdos-program$",
        r"^application/x-font-truetype$",
        r"^application/x-font-opentype$",
        r"^application/x-iso9660-image$",
        r"^application/vnd\.siren\+json$",
        r"^application/x-ms-application$",
        r"^application/vnd\.ms-opentype$",
        r"^application/x-debian-package$",
        r"^application/x-httpd-ea-php54$",
        r"^application/x-shared-scripts$",
        r"^application/x-java-jnlp-file$",
        r"^application/x-httpd-ea-php71$",
        r"^application/x-shockwave-flash$",
        r"^application/vnd\.ogc\.wms_xml$",
        r"^application/x-apple-diskimage$",
        r"^application/x-chrome-extension$",
        r"^application/x-mobipocket-ebook$",
        r"^application/vnd\.1cbn\.v1+json$",
        r"^application/vnd\.ms-fontobject$",
        r"^application/privatetempstorage$",
        r"^application/vnd\.ms-powerpoint$",
        r"^application/vnd\.ms-officetheme$",
        r"^application/vnd\.wv\.csp\+wbxml$",
        r"^application/x-ms-dos-executable$",
        r"^application/x-pkcs7-certificates$",
        r"^application/vnd\.lotus-screencam$",
        r"^application/vnd\.imgur\.v1\+json$",
        r"^value=application/x-font-woff2$",
        r"^application/x-www-form-urlencoded$",
        r"^application/x-typekit-augmentation$",
        r"^application/x-unknown-content-type$",
        r"^application/graphql-response\+json$",
        r"^application/x-research-info-systems$",
        r"^application/vnd\.mapbox-vector-tile$",
        r"^application/vnd\.vimeo\.location\+json$",
        r"^application/opensearchdescription\+xml$",
        r"^application/vnd\.google-earth\.kml\+xml$",
        r"^application/vnd\.ms-excel\.openxmlformat$",
        r"^application/vnd\.android\.package-archive$",
        r"^application/vnd\.vimeo\.currency\.json\+json$",
        r"^application/vnd\.vimeo\.marketplace\.skill\+json$",
        r"^application/vnd\.oasis\.opendocument\.spreadsheet$",
        r"^application/vnd\.disney\.field\.error\.v1\.0\+json$",
        r"^application/vnd\.oasis\.opendocument\.presentation$",
        r"^font/woff2\|application/octet-stream\|font/x-woff2$",
        r"^application/vnd\.google\.octet-stream-compressible$",
        r"^application/vnd\.ms-excel\.sheet\.macroenabled\.12$",
        r"^application/vnd.oasis.opendocument.formula-template$",
        r"^application/vnd\.openxmlformats-officedocument\.spre$",
        r"^application/vnd\.openxmlformats-officedocument\.spreadsheetml\.sheet$",
        r"^application/vnd\.openxmlformats-officedocument\.presentationml\.slideshow",
        r"^application/vnd\.openxmlformats-officedocument\.presentationml\.presentation$",
        r"^applications/javascript$",
        r"^httpd/unix-directory$",
        r"^binary/octet-stream$",
        r"^Content-Type$",
        r"^javascript charset=UTF-8$",
        r"^javascriptcharset=UTF-8$",
        r"^model/usd$",
        r"^model/stl$",
        r"^model/obj$",
        r"^model/gltf-binary$",
        r"^multipart/form-data$",
        r"^multipart/x-mixed-replace$",
        r"^octet/stream$",
    ]

EXTENSION_MAP = {
        ".midi" : content_type_midi_regex,
        ".mid"  : content_type_midi_regex,
        ".zip"  : content_type_compressed_regex,
        ".bz2"  : content_type_compressed_regex,
        ".lz"   : content_type_compressed_regex,
        ".Z"    : content_type_compressed_regex,
        ".rar"  : content_type_compressed_regex,
        ".gz"   : content_type_compressed_regex,
        ".jpg"  : content_type_image_regex,
        ".jpeg" : content_type_image_regex,
        ".png"  : content_type_image_regex,
        ".gif"  : content_type_image_regex,
        ".pdf"  : content_type_pdf_regex,
        ".rm"   : content_type_audio_regex,
        ".mp3"  : content_type_audio_regex,
        ".wav"  : content_type_audio_regex,
        ".flac" : content_type_audio_regex,
        ".mp4"  : content_type_video_regex,
        ".wmv"  : content_type_video_regex,
        ".mkv"  : content_type_video_regex,
        ".swf"  : content_type_video_regex,
        ".ogv"  : content_type_video_regex,
        ".mov"  : content_type_video_regex,
        ".mpg"  : content_type_video_regex,
        ".docx" : content_type_doc_regex,
    }

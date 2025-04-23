import random, hashlib, time, re, string, json
from config import *
from urllib.parse import urlsplit
from datetime import datetime, timezone
from elasticsearch import NotFoundError, RequestError
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError, RequestError

def sanitize_url(url):
    url = url.strip()
    url = url.rstrip()
    url = re.sub(r'^“(.*)"', r"\1", url)
    url = re.sub(r"^”(.*)”$", r"\1", url)
    url = re.sub(r"^“(.*)“$", r"\1", url)
    url = re.sub(r'^"(.*)"$', r"\1", url)
    url = re.sub(r"^“(.*)”$", r"\1", url)
    url = re.sub(r"^‘(.*)’$", r"\1", url)
    url = re.sub(r'^"(.*)\'$', r"\1", url)
    url = re.sub(r"^\'(.*)\'$", r"\1", url)
    url = re.sub(r'^”(.*)″$', r"\1", url)
    url = re.sub(r"^(.+)#.*$", r"\1", url)
    url = re.sub("^www.", "http://www.", url)
    if re.search(r"^http:[^/][^/]", url):
        url = re.sub("^http:", "http://", url)
    if re.search(r"^http:/[^/]", url):
        url = re.sub("^http:/", "http://", url)
    if re.search(r"^https:[^/][^/]", url):
        url = re.sub("^https:", "https://", url)
    if re.search(r"^https:/[^/]", url):
        url = re.sub("^https:/", "https://", url)
    url = re.sub("^ps://", "https://", url)
    url = re.sub("^ttps://", "https://", url)
    url = re.sub("^[a-zA-Z.“(´]https://", "https://", url)
    url = re.sub("^[a-zA-Z.“(´]http://", "http://", url)
    url = re.sub("^https[a-zA-Z.“(´]://", "https://", url)
    url = re.sub("^http[.“(´]://", "http://", url)
    url = re.sub("^htto://", "http://", url)
    url = re.sub("^https: / /", "https://", url)
    url = re.sub("^://", "https://", url)
    url = re.sub("^htt://", "http://", url)
    url = re.sub("^Mh ttp://", "http://", url)
    url = re.sub("^htpps://", "https://", url)
    url = re.sub("^httpp://", "https://", url)
    url = re.sub("^http:s//", "https://", url)
    url = re.sub("^hthttps://", "https://", url)
    url = re.sub("^httsp://", "https://", url)
    url = re.sub("^htts://", "https://", url)
    url = re.sub("^htp://http//", "http://", url)
    url = re.sub("^htp://", "http://", url)
    url = re.sub("^htttps://", "https://", url)
    url = re.sub("^https:https://", "https://", url)
    url = re.sub("^hhttp://", "http://", url)
    url = re.sub("^http:/http://", "http://", url)
    url = re.sub("^https https://", "https://", url)
    url = re.sub("^httpshttps://", "https://", url)
    url = re.sub("^https://https://", "https://", url)
    url = re.sub('^"https://', "https://", url)
    url = re.sub("^http:www", "http://www", url)
    url = re.sub("^httpd://", "https://", url)
    url = re.sub("^htps://", "https://", url)
    url = re.sub("^https: //", "https://", url)
    url = re.sub("^http2://", "https://", url)
    url = re.sub("^https : //", "https://", url)
    url = re.sub("^htttp://", "http://", url)
    url = re.sub("^ttp://", "http://", url)
    url = re.sub("^https%3A//", "https://", url)
    url = re.sub("^%20https://", "https://", url)
    url = re.sub("^%20http://", "http://", url)
    url = re.sub("^%22mailto:", "mailto:", url)
    url = re.sub("^httpqs://", "https://www.", url)
    return url


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

def hash_url(url):
    return hashlib.sha256(url.encode('utf-8')).hexdigest()

def remove_jsessionid_with_semicolon(url):
    pattern = r';jsessionid=[^&?]*'
    cleaned_url = re.sub(pattern, '', url)
    return cleaned_url

def db_insert_if_new_url(url='', isopendir=None, visited=None, source='', content_type='', words='',
                         isnsfw='', resolution='', parent_host='', email=None, db=None, debug=False):

    if debug:
        print(f"[DEBUG] visited param type: {type(visited)} - value: {visited}")

    host = urlsplit(url)[1]
    url = remove_jsessionid_with_semicolon(url)
    now_iso = datetime.now(timezone.utc).isoformat()
    doc_id = hash_url(url)

    try:
        existing_doc = None
        if debug:
            try:
                existing_doc = db.con.get(index=URLS_INDEX, id=doc_id)["_source"]
            except Exception:
                pass

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

            for i, part in enumerate(reversed(host_parts[-MAX_HOST_LEVELS:])):
                insert_only_fields[f"host_level_{i+1}"] = part

            for i, part in enumerate(dir_parts[:MAX_DIR_LEVELS]):
                insert_only_fields[f"directory_level_{i+1}"] = part

        # Fields that may be updated
        doc = {}
        if content_type: doc["content_type"] = content_type
        if words: doc["words"] = words
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
        return True

    except Exception as e:
        print(f"[Elasticsearch] ❌ Error inserting URL '{url}': {type(e).__name__} - {e}")
        return False

def get_url_from_file():
    with open(URL_FILE, 'r', encoding='utf-8') as file:
        urls=json.load(file)
        random.shuffle(urls)
        return urls

def get_random_unvisited_domains(db, size=RANDOM_SITES_QUEUE):
    """Randomly selects between different spreading strategies."""
    try:
        choice = random.random()
        if choice < 0.5:
            return get_url_from_file()
        elif choice < 0.6:
            print('Fewest urls')
            return get_least_covered_random_hosts(db, size=size)
        elif choice < 0.7:
            print('Less visited')
            return get_urls_from_least_visited_hosts(db, size=size)
        elif choice < 0.8:
            print('Oldest')
            return get_oldest_unvisited_urls_from_bucket(db, size=size)
        elif choice < 0.9:
            print('Host Prefix')
            return get_urls_by_random_bucket_and_host_prefix(db, size=size)
        else:
            print('Random')
            return get_random_host_domains(db, size=size)
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
        print("Unhandled error in get_random_unvisited_domains:", e)
        return []
    return []

def get_urls_by_random_bucket_and_host_prefix(db, size=100):
    """Get 1 unvisited URL per host from a random bucket where host starts with a random character."""
    for attempt in range(MAX_ES_RETRIES):
        random_bucket = random.randint(0, ELASTICSEARCH_RANDOM_BUCKETS - 1)
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
            random.shuffle(urls)
            return urls
    return []

def get_oldest_unvisited_urls_from_bucket(db, size=100):
    """Get the oldest unvisited URLs from a random bucket using created_at timestamp."""
    for attempt in range(MAX_ES_RETRIES):
        random_bucket = random.randint(0, ELASTICSEARCH_RANDOM_BUCKETS - 1)

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
            random.shuffle(hits)  # Shuffle the list in-place
            return [{
                "url": hit["_source"]["url"],
                "host": hit["_source"]["host"]
            } for hit in hits]

    return []


def get_random_host_domains(db, size=100):
    """Original logic: get unvisited URLs from random hosts."""
    for attempt in range(MAX_ES_RETRIES):
        random_bucket = random.randint(0, ELASTICSEARCH_RANDOM_BUCKETS - 1)
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
            return [{
                "url": r["inner_hits"]["random_hit"]["hits"]["hits"][0]["_source"]["url"],
                "host": r["_source"]["host"]
            } for r in results]
        return []

def db_create_database(initial_url, db):
    print("Creating Elasticsearch index structure.")
    #try:
    #    host = urlsplit(initial_url)[1]
    #except ValueError:
    #    print("Invalid initial URL:", initial_url)
    #    return False

    now_iso = datetime.now(timezone.utc).isoformat()

    # Define mappings for the URLS_INDEX
    urls_mapping = {
        "mappings": {
            "properties": {
                "url": {"type": "keyword"},
                "visited": {"type": "boolean"},
                "isopendir": {"type": "boolean"},
                "isnsfw": {"type": "float"},
                "content_type": {"type": "keyword"},
                "source": {"type": "keyword"},
                "words": {"type": "keyword"},
                "host": {"type": "keyword"},
                "parent_host": {"type": "keyword"},
                "host_levels": {"type": "keyword"},
                "directory_levels": {"type": "keyword"},
                "host_levels": {"type": "keyword"},
                **{
                    f"directory_level_{i+1}": {"type": "keyword"}
                    for i in range(MAX_DIR_LEVELS)
                },
                **{
                    f"host_level_{i+1}": {"type": "keyword"}
                    for i in range(MAX_HOST_LEVELS)
                },
                "emails": {"type": "keyword"},
                "resolution": {"type": "integer"},
                "random_bucket": {"type": "integer"},
                "created_at": {"type": "date"},
                "updated_at": {"type": "date"}
            }
        }
    }

    try:
        if not db.con.indices.exists(index=URLS_INDEX):
            db.con.indices.create(index=URLS_INDEX, body=urls_mapping)
            print("Created {} index.".format(URLS_INDEX))
            db_insert_if_new_url(url=initial_url, source='db_create_database', parent_host=urlsplit(initial_url)[1], db=db)
            print("Inserted initial url {}.".format(initial_url))
        return True
    except Exception as e:
        print("Error creating indices or inserting initial document:", e)
        return False

def get_urls_from_least_visited_hosts(db, size=100):
    """Fetch 1 truly unvisited URL per host from a random bucket."""
    for attempt in range(MAX_ES_RETRIES):
        random_bucket = random.randint(0, ELASTICSEARCH_RANDOM_BUCKETS - 1)

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

        if results:
            random.shuffle(results)
            return [{
                "url": r["inner_hits"]["least_visited_hit"]["hits"]["hits"][0]["_source"]["url"],
                "host": r["_source"]["host"]
            } for r in results]

    return []



def get_host_levels(hostname):
    """Returns all host levels from right (TLD) to left (subdomain)."""
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

def get_least_covered_random_hosts(db, size=100):
    """Returns 'size' hosts from a random bucket with the fewest unvisited URLs, and one random URL per host."""
    for attempt in range(MAX_ES_RETRIES):
        random_bucket = random.randint(0, ELASTICSEARCH_RANDOM_BUCKETS - 1)

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
        r"^audio/mpeg$",
        r"^audio/opus$",
        r"^audio/x-rpm$",
        r"^audio/x-wav$",
        r"^audio/unknown$",
        r"^audio/mpegurl$",
        r"^audio/x-scpls$",
        r"^audio/x-ms-wma$",
        r"^application/mp3$",
        r"^audio/x-mpegurl$",
        r"^audio/x-pn-realaudio$",
    ]

content_type_pdf = [
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
        r"^image/x-photoshop$",         
        r"^image/x-coreldraw$",        
        r"^image/vnd\.wap\.wbmp$",
        r"^image/x\.fb\.keyframes$",        
        r"^image/vnd\.microsoft\.icon$",
        r"^application/jpg$",        
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
        r"^video/quicktime$",
        r"^video/x-ms-wmv$",
        r"^video/x-ms-asf$",
        r"^video/x-msvideo$",
        r"^video/vnd\.dlna\.mpeg-tts$",
        r"^application/avi$",
        ]

content_type_plain_text_regex = [
        r"^\.js$",
        r"^text/js$",
        r"^text/xml$",
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
        r"^application/ld\+json$",
        r"^application/ion\+json$",
        r"^application/hal\+json$",
        r"^application/stream\+json$",
        r"^application/problem\+json$",
        r"^text/0\.4/hammer\.min\.js$",
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
        r"^file$",
        r"^\*/\*$",
        r"^woff2$",
        r"^unknown$",
        r"^font/ttf$",
        r"^font/otf$",
        r"^font/woff$",
        r"^font/woff2$",
        r"^font/truetype$",
        r"^x-font/ttf$",
        r"^font/x-woff$",
        r"^x-font/woff$",
        r"^font/x-woff2$",
        r"^font/opentype$",
        r"^text/css$",
        r"^text/javascript$",
        r"^application/\*$",
        r"^application/xml$",
        r"^application/x-j$",
        r"^application/rar$",
        r"^application/zip$",
        r"^application/doc$",
        r"^application/xls$",
        r"^application/jwt$",
        r"^application/rtf$",
        r"^application/ogg$",
        r"^application/csv$",
        r"^application/wmv$",
        r"^application/epub$",
        r"^application/node$",
        r"^application/xlsx$",
        r"^application/docx$",
        r"^application/wasm$",
        r"^application/woff$",
        r"^application/mobi$",
        r"^application/gzip$",
        r"^application/save$",
        r"^application/null$",
        r"^application/zlib$",
        r"^application/x-xz$",
        r"^application/json$",
        r"^application/x-sh$",
        r"^application/font$",
        r"^application/x-twb$",
        r"^application/x-tar$",
        r"^application/x-rar$",
        r"^application/\.zip$",
        r"^application/\.rar$",
        r"^application/x-msi$",
        r"^application/x-zip$",
        r"^application/x-xar$",
        r"^application/x-tgif$",
        r"^application/x-perl$",
        r"^application/x-gzip$",
        r"^application/binary$",
        r"^application/msword$",
        r"^application/msword$",
        r"^application/x-woff$",
        r"^application/msexcel$",
        r"^application/unknown$",
        r"^application/xml-dtd$",
        r"^application/x-bzip2$",
        r"^application/x-binary$",
        r"^application/rdf\+xml$",
        r"^application/font-otf$",
        r"^application/download$",
        r"^application/rss\+xml$",
        r"^application/ms-excel$",
        r"^application/font-ttf$",
        r"^application/x-msword$",
        r"^application/pgp-keys$",
        r"^application/x-bibtex$",
        r"^application/pkix-crl$",
        r"^application/x-tar-gz$",
        r"^application/font-sfnt$",
        r"^application/ttml\+xml$",
        r"^application/xslt\+xml$",
        r"^application/dash\+xml$",
        r"^application/x-dosexec$",
        r"^application/epub\+zip$",
        r"^application/atom\+xml$",
        r"^application/x-msexcel$",
        r"^application/pkix-cert$",
        r"^application/x-mpegurl$",
        r"^application/font-woff$",
        r"^application/postscript$",
        r"^application/x-font-ttf$",
        r"^application/x-font-otf$",
        r"^application/x-rss\+xml$",
        r"^application/ecmascript$",
        r"^application/x-protobuf$",
        r"^application/pkcs7-mime$",
        r"^application/font-woff2$",
        r"^application/javascript$",
        r"^application/oct-stream$",
        r"^application/vnd\.yt-ump$",
        r"^application/x-font-woff$",
        r"^application/x-xpinstall$",
        r"^application/x-httpd-php$",
        r"^application/x-directory$",
        r"^application/x-troff-man$",
        r"^application/java-archive$",
        r"^application/x-javascript$",
        r"^application/x-msdownload$",
        r"^application/x-font-woff2$",
        r"^application/octet-stream$",
        r"^application/vnd\.ms-word$",
        r"^application/x-executable$",
        r"^application/x-base64-frpc$",
        r"^application/pgp-signature$",
        r"^application/grpc-web-text$",
        r"^application/vnd\.ms-excel$",
        r"^application/force-download$",
        r"^x-application/octet-stream$",
        r"^application/x-x509-ca-cert$",
        r"^application/grpc-web\+proto$",
        r"^application/x-msdos-program$",
        r"^application/x-font-truetype$",
        r"^application/x-font-opentype$",
        r"^application/x-iso9660-image$",
        r"^application/x-ms-application$",
        r"^application/x-zip-compressed$",
        r"^application/x-rar-compressed$",
        r"^application/vnd\.ms-opentype$",
        r"^application/x-debian-package$",
        r"^application/x-httpd-ea-php54$",
        r"^application/x-java-jnlp-file$",
        r"^application/x-httpd-ea-php71$",
        r"^application/x-gtar-compressed$",
        r"^application/x-shockwave-flash$",
        r"^application/vnd\.ogc\.wms_xml$",
        r"^application/vnd.ms-fontobject$",
        r"^application/x-apple-diskimage$",
        r"^application/x-chrome-extension$",
        r"^application/x-mobipocket-ebook$",
        r"^application/privatetempstorage$",
        r"^application/vnd\.ms-powerpoint$",
        r"^application/vnd\.ms-officetheme$",
        r"^application/x-ms-dos-executable$",
        r"^application/vnd\.apple\.mpegurl$",
        r"^application/x-pkcs7-certificates$",
        r"^application/x-typekit-augmentation$",
        r"^application/x-unknown-content-type$",
        r"^application/x-research-info-systems$",
        r"^application/vnd\.ms-word\.document\.12$",
        r"^application/opensearchdescription\+xml$",
        r"^application/vnd\.google-earth\.kml\+xml$",
        r"^application/vnd\.ms-excel\.openxmlformat$",
        r"^application/vnd\.android\.package-archive$",
        r"^application/vnd\.oasis\.opendocument\.text$",
        r"^application/x-zip-compressedcontent-length:",
        r"^application/vnd\.oasis\.opendocument\.spreadsheet$",
        r"^application/vnd\.oasis\.opendocument\.presentation$",
        r"^application/vnd\.google\.octet-stream-compressible$",
        r"^application/vnd\.ms-excel\.sheet\.macroenabled\.12$",
        r"^application/vnd.oasis.opendocument.formula-template$",
        r"^application/vnd\.openxmlformats-officedocument\.spre$",
        r"^application/vnd\.adobe\.air-application-installer-package\+zip$",
        r"^application/vnd\.openxmlformats-officedocument\.spreadsheetml\.sheet$",
        r"^application/vnd\.openxmlformats-officedocument\.presentationml\.slideshow",
        r"^application/vnd\.openxmlformats-officedocument\.wordprocessingml\.document$",
        r"^application/vnd\.openxmlformats-officedocument\.wordprocessingml\.template$",
        r"^application/vnd\.openxmlformats-officedocument\.presentationml\.presentation$",
        r"^applications/javascript$",
        r"^httpd/unix-directory$",
        r"^binary/octet-stream$",
        r"^Content-Type$",
        r"^javascript charset=UTF-8$",
        r"^javascriptcharset=UTF-8$",
        r"^model/usd$",
        r"^model/obj$",
        r"^model/gltf-binary$",
        r"^multipart/x-zip$",
        r"^multipart/form-data$",
        r"^multipart/x-mixed-replace$",
        r"^octet/stream$",
    ]

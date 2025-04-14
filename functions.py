import random, hashlib, time, re
from config import *
from urllib.parse import urlsplit
from datetime import datetime, timezone
from elasticsearch import NotFoundError, RequestError
from elasticsearch import Elasticsearch

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

def db_create_database(initial_url, db):
    print("Creating Elasticsearch index structure.")
    try:
        host = urlsplit(initial_url)[1]
    except ValueError:
        print("Invalid initial URL:", initial_url)
        return False

    now_iso = datetime.now(timezone.utc).isoformat()

    # Define mappings for the 'urls' index
    urls_mapping = {
        "mappings": {
            "properties": {
                "url": {"type": "keyword"},
                "visited": {"type": "boolean"},
                "isopendir": {"type": "boolean"},
                "isnsfw": {"type": "float"},
                "content_type": {"type": "text"},
                "source": {"type": "keyword"},
                "words": {"type": "keyword"},
                "host": {"type": "keyword"},
                "parent_host": {"type": "keyword"},
                "resolution": {"type": "integer"},
                "random_bucket": {"type": "integer"},
                "created_at": {"type": "date"},
                "updated_at": {"type": "date"}
            }
        }
    }

    # Define mappings for the 'emails' index
    emails_mapping = {
        "mappings": {
            "properties": {
                "url": {"type": "keyword"},
                "email": {"type": "keyword"}
            }
        }
    }

    try:
        if not db.con.indices.exists(index="urls"):
            db.con.indices.create(index="urls", body=urls_mapping)
            print("Created 'urls' index.")
        if not db.con.indices.exists(index="emails"):
            db.con.indices.create(index="emails", body=emails_mapping)
            print("Created 'emails' index.")

        # Insert the initial URL as a document
        doc = {
            "url": initial_url,
            "visited": False,
            "isopendir": False,
            "isnsfw": 0.0,
            "source": "manual",
            "host": host,
            "parent_host": None,
            "resolution": None,
            "random_bucket": random.randint(0, ELASTICSEARCH_RANDOM_BUCKETS - 1),
            "created_at": now_iso,
            "updated_at": now_iso
        }

        # Use hashed URL as document ID
        doc_id = hash_url(initial_url)

        db.con.index(index="urls", id=doc_id, document=doc)
        print(f"Inserted initial URL into 'urls' index with hash ID: {doc_id}")
        return True
    except Exception as e:
        print("Error creating indices or inserting initial document:", e)
        return False

def get_random_unvisited_domains(db):
    try:
        for attempt in range(MAX_ES_RETRIES):
            random_bucket = random.randint(0, ELASTICSEARCH_RANDOM_BUCKETS - 1)
            query_body = {
                "size": ELASTICSEARCH_RANDOM_BUCKETS,
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
                "collapse": {"field": "host"},
                "sort": {
                    "_script": {
                        "type": "number",
                        "script": {
                            "lang": "painless",
                            "source": "Math.random()"
                        },
                        "order": "asc"
                    }
                }
            }

            try:
                response = db.con.search(index="urls", body=query_body)
                results = response.get('hits', {}).get('hits', [])

                if results:
                    return [{"url": r["_source"]["url"], "host": r["_source"]["host"]} for r in results]

            except NotFoundError as e:
                if "index_not_found_exception" in str(e):
                    print("Elasticsearch index missing. Creating now...")
                    db_create_database(INITIAL_URL, db=db)
                else:
                    print(f"[Attempt {attempt+1}] Elasticsearch query failed:", e)
            except RequestError as e:
                print(f"[Attempt {attempt+1}] Elasticsearch request error:", e)
            except Exception as e:
                print(f"[Attempt {attempt+1}] Elasticsearch unknown error:", e)
            time.sleep(ES_RETRY_DELAY)

        print("No unvisited domains found after retries.")
        return []
    except Exception as e:
        print("Unhandled error:", e)
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
        r"^image/dicomp$", 
        r"^image/x-png$",
        r"^image/x-eps$",
        r"^image/\{png\}$", 
        r"^image/x-icon$",
        r"^image/vnd\.dwg$",    
        r"^image/svg\+xml$",
        r"^image/x-ms-bmp$",        
        r"^image/x-photoshop$",         
        r"^image/x-coreldraw$",        
        r"^image/vnd\.wap\.wbmp$",
        r"^image/vnd\.microsoft\.icon$",
        r"^application/jpg$",        
    ]

content_type_plain_text_regex = [
        r"^text/rtf$",
        r"^text/plain$",
        r"^application/text$",
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
        r"^-$",
        r"^\*$",
        r"^None$",
        r"^\*/\*$",
        r"^woff2$",
        r"^font/ttf$",
        r"^font/otf$",
        r"^app/json$",
        r"^font/woff$",
        r"^font/woff2$",
        r"^x-font/ttf$",
        r"^font/x-woff$",
        r"^x-font/woff$",
        r"^font/x-woff2$",
        r"^font/opentype$",
        r"^application/\*$",
        r"^application/xml$",
        r"^application/x-j$",
        r"^application/rar$",
        r"^application/zip$",
        r"^application/avi$",
        r"^application/doc$",
        r"^application/xls$",
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
        r"^application/json$",
        r"^application/mobi$",
        r"^application/gzip$",
        r"^application/save$",
        r"^application/null$",
        r"^application/zlib$",
        r"^application/x-xz$",
        r"^application/x-sh$",
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
        r"^application/ld\+json$",
        r"^application/rdf\+xml$",
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
        r"^application/hal\+json$",
        r"^application/ttml\+xml$",
        r"^application/xslt\+xml$",
        r"^application/dash\+xml$",
        r"^application/x-dosexec$",
        r"^application/ion\+json$",
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
        r"^application/problem\+json$",
        r"^application/grpc-web-text$",
        r"^application/vnd\.ms-excel$",
        r"^text/0\.4/hammer\.min\.js$",
        r"^application/force-download$",
        r"^application/vnd\.api\+json$",
        r"^application/x-thrift\+json$",
        r"^application/json\+protobuf$",
        r"^x-application/octet-stream$",
        r"^application/x-x509-ca-cert$",
        r"^application/manifest\+json$",
        r"^application/importmap\+json$",
        r"^application/grpc-web\+proto$",
        r"^application/x-msdos-program$",
        r"^application/x-amz-json-1\.1$",
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
        r"^application/speculationrules\+json$",
        r"^application/x-unknown-content-type$",
        r"^application/x-research-info-systems$",
        r"^application/vnd.inveniordm\.v1\+json$",
        r"^application/vnd\.ms-word\.document\.12$",
        r"^application/opensearchdescription\+xml$",
        r"^application/vnd\.google-earth\.kml\+xml$",
        r"^application/vnd\.ms-excel\.openxmlformat$",
        r"^application/vnd\.maxmind\.com-city\+json$",
        r"^application/vnd\.android\.package-archive$",
        r"^application/vnd\.oasis\.opendocument\.text$",
        r"^application/vnd\.radio-canada\.neuro\+json$",
        r"^application/x-zip-compressedcontent-length:",
        r"^application/vnd\.maxmind\.com-country\+json$",
        r"^application/vnd\.maxmind\.com-insights\+json$",
        r"^application/vnd\.contentful\.delivery\.v1\+json$",
        r"^application/vnd\.spring-boot\.actuator\.v3\+json$",
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
        r"^binary/octet-stream$",
        r"^Content-Type$",
        r"^javascript charset=UTF-8$",
        r"^model/usd$",
        r"^model/obj$",
        r"^model/gltf-binary$",
        r"^multipart/x-zip$",
        r"^multipart/form-data$",
        r"^multipart/x-mixed-replace$",
        r"^octet/stream$",
        r"^text/js$",
        r"^text/xml$",
        r"^text/css$",
        r"^text/csv$",
        r"^text/vtt$",
        r"^text/x-sh$",
        r"^text/json$",
        r"^text/x-js$",
        r"^text/vcard$",
        r"^text/x-tex$",
        r"^text/x-perl$",
        r"^text/x-chdr$",
        r"^text/x-json$",
        r"^text/turtle$",
        r"^text/x-vcard$",
        r"^text/calendar$",
        r"^text/markdown$",
        r"^text/x-bibtex$",
        r"^text/directory$",
        r"^text/javascript$",
        r"^text/x-vcalendar$",
        r"^text/x-component$",
        r"^text/x-comma-separated-values$",
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
    ]

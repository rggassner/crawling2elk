#!venv/bin/python3
import os, re, time, hashlib, signal, random, argparse, urllib3, warnings, bs4.builder
import numpy as np
from config import *
if CATEGORIZE_NSFW:
    import opennsfw2 as n2
    model = n2.make_open_nsfw_model()
from functions import *
from bs4 import BeautifulSoup
from urllib.parse import urlsplit
from seleniumwire import webdriver
from fake_useragent import UserAgent
from seleniumwire.utils import decode
from urllib.parse import unquote,urljoin,urlparse
from pathlib import PurePosixPath
import absl.logging
absl.logging.set_verbosity('error')
from PIL import Image, UnidentifiedImageError
from io import BytesIO
from datetime import datetime, timezone
from urllib3.exceptions import InsecureRequestWarning
from collections import Counter
warnings.filterwarnings("ignore", category=InsecureRequestWarning)
warnings.filterwarnings("ignore", category=Warning, message=".*verify_certs=False is insecure.*")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



url_functions = []
content_type_functions = []

#model = None

##used to generate wordlist
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

## Verify if host is in a blocklist.
def is_host_block_listed(url):
    for regex in host_regex_block_list:
        if re.search(regex, url, flags=re.I | re.U):
            return True
    return False

## Verify if url is in a blocklist.
def is_url_block_listed(url):
    for regex in url_regex_block_list:
        if re.search(regex, url, flags=re.I | re.U):
            return True
    return False

## Verify if url is in a allowlist.
def is_host_allow_listed(url):
    for regex in host_regex_allow_list:
        if re.search(regex, url, flags=re.I | re.U):
            return True
    return False

def build_conditional_update_script(doc: dict) -> tuple[str, dict]:
    script_lines = []
    params = {}
    for key, value in doc.items():
        params[key] = value
        if key == "visited":
            script_lines.append("""
                if (ctx._source.visited == null || ctx._source.visited == false) {
                    ctx._source.visited = params.visited;
                }
            """)
        elif key != "updated_at":
            script_lines.append(f"""
                if (ctx._source['{key}'] != params['{key}']) {{
                    ctx._source['{key}'] = params['{key}'];
                }}
            """)
    # Only update updated_at if any other field changed
    script_lines.append("""
        if (ctx._source != params.existing_source_snapshot) {
            ctx._source.updated_at = params.updated_at;
        }
    """)

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

def extract_top_words_from_text(text: str) -> list[str]:
    if WORDS_REMOVE_SPECIAL_CHARS:
        text = re.sub(r'[^\w\s]', ' ', text, flags=re.UNICODE)
    if WORDS_TO_LOWER:
        text = text.lower()

    words = [word for word in text.split() if WORDS_MIN_LEN < len(word) <= WORDS_MAX_LEN]
    most_common = Counter(words).most_common(WORDS_MAX_WORDS)
    return [word for word, _ in most_common]


def is_open_directory(content, content_url):
    host=urlsplit(content_url)[1]
    pattern=r'<title>Index of /|<h1>Index of /|\[To Parent Directory\]</A>|<title>'+re.escape(host)+' - /</title>|_sort=\'name\';SortDirsAndFilesName();'
    if re.findall(pattern,content):
        print('### Is open directory -{}-'.format(content_url))
        return True
    return False

def function_for_url(regexp_list):
    def get_url_function(f):
        for regexp in regexp_list:
            url_functions.append((re.compile(regexp, flags=re.I | re.U), f))
        return f
    return get_url_function

## url unsafe {}|\^~[]`
## regex no need to escape '!', '"', '%', "'", ',', '/', ':', ';', '<', '=', '>', '@', and "`"
@function_for_url(
    [
        r"^(\/|\.\.\/|\.\/)",
        r"^[0-9\-\./\?=_\&\s%@<>\(\);\+!,\w\$\'–’—”“a°§£Ã¬´c�í¦a]+$",
        r"^[0-9\-\./\?=_\&\s%@<>\(\);\+!,\w\$\'–’—”“a°§£Ã¬´c]*[\?\/][0-9\-\./\?=_\&\s%@<>\(\);\+!,\w\$\'–’—”“a°§£Ã¬:\"¶c´™*]+$",
    ]
)
def relative_url(args):
    out_url = urljoin(args['parent_url'], args['url'])
    parent_host=urlsplit(args['parent_url'])[1]
    db_insert_if_new_url(url=out_url, visited=False, source="relative_url",parent_host=parent_host,db=args['db'])
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
    parent_host=urlsplit(args['parent_url'])[1]
    db_insert_if_new_url(url=args['url'],source="full_url",visited=False,parent_host=parent_host,db=args['db'])
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
            parent_host=urlsplit(args['parent_url'])[1]
            db_insert_if_new_url(url=args['parent_url'],email=address,source='email_url',parent_host=parent_host,db=args['db'])
            return True
        else:
            return False
    else:
        return False

def get_links(soup, content_url,db):
    #If you want to grep some patterns, use the code below.
    #pattern=r'"file":{".*?":"(.*?)"}'
    #for script in soup.find_all('script',type="text/javascript"):
    #    if re.search(pattern,str(script)):
    #        print(re.search(pattern,str(script))[1])
    tags = soup("a")
    for tag in tags:
        url = tag.get("href", None)

        if type(url) != str:
            continue
        else:
            url = sanitize_url(url)
        found = False
        host=urlsplit(url)[1]
        #the below block ensures that if link takes to a internal directory of the server, it will use the original host
        if host == '':
            host=urlsplit(content_url)[1]
        if not is_host_block_listed(host) and is_host_allow_listed(host) and not is_url_block_listed(url):
            for regex, function in url_functions:
                m = regex.search(url)
                if m:
                    found = True
                    function({'url':url,'parent_url':content_url,'db':db})
                    continue
            if not found:
                out_url = urljoin(content_url, url)
                print("Unexpected URL -{}- Reference URL -{}-".format(url, content_url))
                print("Unexpected URL. Would this work? -{}-".format(out_url))   
                parent_host=urlsplit(content_url)[1]
                if BE_GREEDY:
                    db_insert_if_new_url(url=out_url,source="get_links",visited=False,parent_host=parent_host,db=db)
    return True

def function_for_content_type(regexp_list):
    def get_content_type_function(f):
        for regexp in regexp_list:
            content_type_functions.append((re.compile(regexp, flags=re.I | re.U), f))
        return f
    return get_content_type_function

def get_directory_tree(url):
    #Host will have scheme, hostname and port
    host='://'.join(urlsplit(url)[:2])
    dtree=[]
    for iter in range(1,len(PurePosixPath(unquote(urlparse(url).path)).parts[0:])):
        dtree.append(str(host+'/'+'/'.join(PurePosixPath(unquote(urlparse(url).path)).parts[1:-iter])))
    return dtree

def insert_directory_tree(content_url,db):
    parent_host=urlsplit(content_url)[1]
    for url in get_directory_tree(content_url):
        url = sanitize_url(url)
        db_insert_if_new_url(url=url,words='',content_type='', visited=False,source="insert_directory_tree",parent_host=parent_host,db=db)

@function_for_content_type(content_type_html_regex)
def content_type_download(args):
    try:
        soup = BeautifulSoup(args['content'], "html.parser")
    except UnboundLocalError as e:
        print(e)
        return False
    except bs4.builder.ParserRejectedMarkup as e:
        print(e)
        return False
    get_links(soup, args['url'],args['db'])
    words = ''
    if EXTRACT_WORDS:
        words = get_words_from_soup(soup)
    isopendir = is_open_directory(str(soup), args['url'])
    db_insert_if_new_url(url=args['url'],content_type=args['content_type'],isopendir=isopendir,visited=True,words=words,source='content_type_html_regex',parent_host=args['parent_host'],db=args['db'])
    return True

@function_for_content_type(content_type_plain_text_regex)
def content_type_download(args):
    words = ''
    if EXTRACT_WORDS:
        words = get_words(args['content'])
    db_insert_if_new_url(url=args['url'],content_type=args['content_type'],isopendir=False,visited=True,words=words,source='content_type_plain_text_regex',parent_host=args['parent_host'],db=args['db'])
    return True

@function_for_content_type(content_type_image_regex)
def content_type_images(args):
    global model
    npixels=0
    if CATEGORIZE_NSFW or SAVE_ALL_IMAGES:
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
            db_insert_if_new_url(url=args['url'], content_type=args['content_type'],source='content_type_image_regex',isopendir=False, visited=True,parent_host=args['parent_host'],resolution=npixels,db=args['db'])
            return False
        except Image.DecompressionBombError as e:
            db_insert_if_new_url(url=args['url'], content_type=args['content_type'],source='content_type_image_regex',isopendir=False, visited=True,parent_host=args['parent_host'],resolution=npixels,db=args['db'])
            return False
        except OSError:
            db_insert_if_new_url(url=args['url'], content_type=args['content_type'],source='content_type_image_regex',isopendir=False, visited=True,parent_host=args['parent_host'],resolution=npixels,db=args['db'])
            return False
        if SAVE_ALL_IMAGES:
            img.save(IMAGES_FOLDER+'/' + filename, "PNG")
        if CATEGORIZE_NSFW and npixels > MIN_NSFW_RES :
            image = n2.preprocess_image(img, n2.Preprocessing.YAHOO)
            inputs = np.expand_dims(image, axis=0) 
            predictions = model.predict(inputs, verbose=0)
            sfw_probability, nsfw_probability = predictions[0]
            db_insert_if_new_url(args['url'],content_type=args['content_type'],source='content_type_image_regex',visited=True,parent_host=args['parent_host'],isnsfw=nsfw_probability,isopendir=False,resolution=npixels, db=args['db'])
            if nsfw_probability>NSFW_MIN_PROBABILITY:
                print('porn {} {}'.format(nsfw_probability,args['url']))
                if SAVE_NSFW:
                    img.save(NSFW_FOLDER +'/'+ filename, "PNG")
            else:
                if SAVE_SFW:
                    img.save(SFW_FOLDER +'/' +filename, "PNG")
    db_insert_if_new_url(url=args['url'], content_type=args['content_type'],source='content_type_image_regex',isopendir=False, visited=True,parent_host=args['parent_host'],resolution=npixels,db=args['db'])
    return True

@function_for_content_type(content_type_midi_regex)
def content_type_midis(args):
    if DOWNLOAD_MIDIS:
        filename=os.path.basename(urlparse(args['url']).path)
        f = open(MIDIS_FOLDER+'/'+filename, "wb")
        f.write(args['content'])
        f.close()
    db_insert_if_new_url(url=args['url'], content_type=args['content_type'],source='content_type_midi_regex',isopendir=False, visited=True,parent_host=args['parent_host'],db=args['db'])
    return True

@function_for_content_type(content_type_audio_regex)
def content_type_midis(args):
    if DOWNLOAD_AUDIOS:
        filename=os.path.basename(urlparse(args['url']).path)
        f = open(AUDIOS_FOLDER+'/'+filename, "wb")
        f.write(args['content'])
        f.close()
    db_insert_if_new_url(url=args['url'], content_type=args['content_type'],source='content_type_audio_regex',isopendir=False, visited=True,parent_host=args['parent_host'],db=args['db'])
    return True

@function_for_content_type(content_type_pdf)
def content_type_pdfs(args):
    db_insert_if_new_url(url=args['url'], content_type=args['content_type'],isopendir=False, visited=True,source='content_type_pdf',parent_host=args['parent_host'],db=args['db'])
    if not DOWNLOAD_PDFS:
        return True
    filename=os.path.basename(urlparse(args['url']).path)
    f = open(PDFS_FOLDER+'/'+filename, "wb")
    f.write(args['content'])
    f.close()
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

def get_page(url,driver,db):
    driver = read_web(url,driver)
    parent_host=urlsplit(url)[1]
    #main_url=url
    if driver:
        for request in driver.requests:
            if request.response and request.response.headers['Content-Type']:
                url=request.url
                host=urlsplit(url)[1]
                content=decode(request.response.body, request.response.headers.get('Content-Encoding', 'identity'))
                content_type=request.response.headers['Content-Type']
                content_type=sanitize_content_type(content_type)
                if not is_host_block_listed(host) and is_host_allow_listed(host) and not is_url_block_listed(url):
                    if HUNT_OPEN_DIRECTORIES:
                        insert_directory_tree(url,db)
                    found=False
                    for regex, function in content_type_functions:
                        m = regex.search(content_type)
                        if m:
                            found = True
                            function({'url':url,'visited':True, 'content_type':content_type, 'content':content,'source':'get_page','words':'','parent_host':parent_host,'db':db})
                            continue
                    if not found:
                        print("UNKNOWN type -{}- -{}-".format(url, content_type))
    #db_insert_if_new_url(url=main_url,visited=True, source='get_page', db=db)

def break_after(seconds=60):
    def timeout_handler(signum, frame):  # Custom signal handler
        raise TimeoutException
    def function(function):
        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(seconds)
            try:
                res = function(*args, **kwargs)
                signal.alarm(0)  # Clear alarm
                return res
            except TimeoutException:
                print(
                    "Oops, timeout: {} {} {} {} sec reached.".format(
                        seconds, function.__name__, args, kwargs
                    )
                )
            return
        return wrapper
    return function

## This "break_after" is a decorator, not intended for timeouts,
## but for links that take too long downloading, like streamings
## or large files.
@break_after(MAX_DOWNLOAD_TIME)
def read_web(url,driver):
    try:
        if url.startswith('http://'):
            url=HTTPS_EMBED+url
        driver.get(url)
        return driver
    except Exception as e:
        print(e)
        return False

class TimeoutException(Exception):  # Custom exception class
    pass

def initialize_driver():
    user_agent = UserAgent().random
    options = webdriver.ChromeOptions()
    options.add_argument(f'user-agent={user_agent}')
    prefs = {"download.default_directory": DIRECT_LINK_DOWNLOAD_FOLDER,}
    if not CATEGORIZE_NSFW and not SAVE_ALL_IMAGES and not FORCE_IMAGE_LOAD:
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
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("--disable-web-security")
    options.add_argument("--allow-running-insecure-content")
    #options.add_argument('--disable-webrtc')
    #options.add_argument('--disable-geolocation')
    #options.add_argument('--disable-infobars')
    #options.add_argument('--disable-popup-blocking')
    #options.add_argument('--disable-javascript')
    #options.add_argument('--proxy-server=http://your-proxy-server:port')
    #options.add_argument('--proxy-server=http://'+PROXY_HOST+':'PROXY_PORT)
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
                    print('url {}'.format(target_url['url']))
                    del driver.requests
                    get_page(target_url['url'], driver,db)
                    if HUNT_OPEN_DIRECTORIES:
                        insert_directory_tree(target_url['url'],db)
                except UnicodeEncodeError:
                    pass
        driver.quit()

def main():
    global model
    parser = argparse.ArgumentParser(description="URL scanner and inserter.")
    parser.add_argument(
        "command",
        nargs="?",
        choices=["insert", "run"],
        default="run",
        help="Choose 'insert' to insert a URL or 'run' to execute the crawler"
    )
    parser.add_argument(
        "url",
        nargs="?",
        help="The URL to insert (used with 'insert' command)"
    )
    args = parser.parse_args()
    db = DatabaseConnection()
    if args.command == "insert":
        if not args.url:
            print("Error: Please provide a URL to insert.")
        else:
            db_insert_if_new_url(url=args.url, visited=False, source='manual', content_type='', words='', isnsfw='', resolution='', parent_host='', db=db)
    else:
        crawler(db)

    db.close()

if __name__ == "__main__":
    main()


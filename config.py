#! venv/bin/python3

# Used only in the first run
# INITIAL_URL = 'https://crawler-test.com/'
INITIAL_URL = 'https://crawler-test.com/'

# If you input urls using files, feed them here
# Urls will be delete from files after crawling
# and files will be deleted when empty
INPUT_DIR = 'input_url_files'

MAX_URLS_FROM_FILE = 100

# -------------------------------------------
# Elasticsearch connection configuration
# -------------------------------------------

# The hostname or IP address of the Elasticsearch server
ELASTICSEARCH_HOST = '192.168.1.1'

# The port Elasticsearch is listening on (typically 9200 for HTTP/HTTPS)
ELASTICSEARCH_PORT = 9200

# Username for basic authentication
ELASTICSEARCH_USER = 'elastic'

# Password for basic authentication
ELASTICSEARCH_PASSWORD = 'yourpassword'

# Optional path to a CA certificate file for verifying the server's TLS cert
# Set to None to skip custom CA verification (not recommended in production)
ELASTICSEARCH_CA_CERT_PATH = None

# Timeout in seconds for each request to Elasticsearch
# Useful when dealing with long-running queries or slow networks
ELASTICSEARCH_TIMEOUT = 300

# Whether to retry the request if it times out
# Helps improve resilience in the face of network hiccups or brief server issues
ELASTICSEARCH_RETRY = True

# Total number of retry attempts if a request fails or times out
# Applies when ELASTICSEARCH_RETRY is True
ELASTICSEARCH_RETRIES = 5

# Whether to enable HTTP compression for request/response bodies
# Can reduce bandwidth usage, but adds CPU cost — usually safe to enable
ELASTICSEARCH_HTTP_COMPRESS = False

# Whether to verify the server’s SSL certificate
# Should be True in production; set to False only in dev or when using self-signed certs
ELASTICSEARCH_VERIFY_CERTS = False

# In order to avoid multiple workers on the same url
ELASTICSEARCH_RANDOM_BUCKETS = 20

# Name of the index where data will be stored
URLS_INDEX = 'crawler'


# -------------------------------------------
# Selenium configuration
# -------------------------------------------

SELENIUM_WIDTH = 1920
SELENIUM_HEIGHT = 1080
USE_PROXY = False
PROXY_HOST = 'http://10.20.10.19:8123'

# When the url is for a document, where will it be stored.
# This configuration does not affect the other download configuration
# below
DIRECT_LINK_DOWNLOAD_FOLDER = '/dev/null'

BLOCK_CSS = False

# This makes selenium a bit faster if enabled but might make it detectable
PERFORMANCE_OPTIMIZED = False
FORCE_IMAGE_LOAD = False

# -------------------------------------------
# Crawler behavior configuration
# -------------------------------------------

# This option only makes sense to be activated when you have an external
# script packing data to database, since all crawler data is already
# filtered while urls are entering.
REMOVE_INVALID_URLS = False

# If urls that are blocked based on host should be removed from the database.
REMOVE_BLOCKED_HOSTS = False

# If urls that are blocked based on path should be deleted from the database.
REMOVE_BLOCKED_URLS = False

# How long will it  wait until consider the url is not responding
# This will deal with pages asking for basic authentication, and
# streaming urls that never ends.
MAX_DOWNLOAD_TIME = 120

# How many iterations should the python script runs. This does not
# apply to the wrapper, that makes it run continuously.
ITERATIONS = 100

# Files won't be longer than MAX_FILENAME_LENGTH in disk. If it happens
# name will be trunkated, but original extensions are kept.
MAX_FILENAME_LENGTH = 255

# What to download and where to save
DOWNLOAD_MIDIS = True
MIDIS_FOLDER = 'midis'

DOWNLOAD_AUDIOS = False
AUDIOS_FOLDER = 'audios'

DOWNLOAD_PDFS = False
PDFS_FOLDER = 'pdfs'

DOWNLOAD_DATABASES = False
DATABASES_FOLDER = 'databases'

DOWNLOAD_DOCS = False
DOCS_FOLDER = 'docs'

DOWNLOAD_FONTS = False
FONTS_FOLDER = 'fonts'

DOWNLOAD_VIDEOS = False
VIDEOS_FOLDER = 'videos'

DOWNLOAD_ALL_IMAGES = False
IMAGES_FOLDER = 'images'

DOWNLOAD_TORRENTS = False
TORRENTS_FOLDER = 'torrents'

DOWNLOAD_COMPRESSEDS = False
COMPRESSEDS_FOLDER = 'compressed'

# NonSafeForWork parameters
CATEGORIZE_NSFW = False
NSFW_MIN_PROBABILITY = .78
# Minimum number of pixels an image should have in order to be evaluated
MIN_NSFW_RES = 64 * 64
DOWNLOAD_NSFW = False
NSFW_FOLDER = 'images/nsfw'
DOWNLOAD_SFW = False
SFW_FOLDER = 'images/sfw'

# This will include all directories from tree
# might sound aggressive for some websites
HUNT_OPEN_DIRECTORIES = True

# Selenium-wire don't do well with http, so we launch a https
# localhost webservice that allows the content to be embeded and
# crawled
EMBED_PORT = "4443"
HTTPS_EMBED = 'https://localhost:'+EMBED_PORT+'/embed.html?url='

# How many async workers for each instance type
MAX_FAST_WORKERS = 2

# When working with only one worker and if you want to avoid WAFs
FAST_RANDOM_MIN_WAIT = 0
FAST_RANDOM_MAX_WAIT = 0

MAX_SCANNER_WORKERS = 1

# Delay between fast buckets. Used to decrease the elastic search access.
FAST_DELAY = 20

# Word extraction
EXTRACT_WORDS = True
WORDS_REMOVE_SPECIAL_CHARS = True
WORDS_TO_LOWER = True
WORDS_MIN_LEN = 3

# WORDS_MAX_LEN * WORDS_MAX_WORDS should be under 1 million
# for a default elastic search env
WORDS_MAX_LEN = 40
WORDS_MAX_WORDS = 24000

# How many urls should each picking method return
RANDOM_SITES_QUEUE = 100

MAX_DIR_LEVELS = 7
MAX_HOST_LEVELS = 7

# If we should or not save full html to the database
EXTRACT_RAW_WEBCONTENT = True
# If we should or not save rendered text page to the database
EXTRACT_MIN_WEBCONTENT = True

# Should be under 1 million for a default elastic search env
MAX_WEBCONTENT_SIZE = 900000

# search words will be randomly chosen, web searched and crawled
SEARCH_WORDS = [
    "Conan", "Barbarian", "Cimmeria", "Hyborian Age", "Robert E. Howard",
]

# be_greedy = True - Save urls to database that might not work,
# since have not matched any regex.
BE_GREEDY = False

# Do not crawl these domains.
HOST_REGEX_BLOCK_LIST = [
    r'localhost:4443$',
    r'(^|\.)google$',
    r'(^|\.)google\.com$',
]

# Do not crawl urls that match any of these regexes
URL_REGEX_BLOCK_LIST = [
    '/noticias/modules/noticias/modules/',
    '/images/images/images/images/',
    '/plugins/owlcarousel/plugins/',
]

# Only crawl domains that match this regex
HOST_REGEX_ALLOW_LIST = [r'.*']

# A weight for every method of url picking
METHOD_WEIGHTS = {
    "web_search":   1,
    "fewest_urls":  1,
    "less_visited": 1,
    "oldest":       2,
    "host_prefix":  1,
    "random":       1
}

# Scanner options
SERVICES_INVENTORY = "/usr/share/nmap/nmap-services"

# Chance for running the algorythm to generate a non conventional port
RANDOM_PORT_CHANCE = 0.1

# The scanner should focus on these networks
SCAN_NETWORKS = [
    "0.0.0.0/0"
]

# The scanner should avoid these networks
NOSCAN_NETWORKS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "0.0.0.0/8",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "100.64.0.0/10",
    "169.254.0.0/16"
]

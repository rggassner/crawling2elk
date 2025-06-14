#!/usr/bin/python3

# Used only in the first run
# INITIAL_URL = 'https://crawler-test.com/'
INITIAL_URL = 'https://crawler-test.com/'

# If you input urls using files, feed them here
# Urls will be delete from files after crawling
# and files will be deleted when empty
INPUT_DIR = "input_url_files"
MAX_URLS_FROM_FILE = 100

# Elasticsearch connection configuration
ELASTICSEARCH_HOST = "127.0.0.1"
ELASTICSEARCH_PORT = 9200
ELASTICSEARCH_USER = 'elastic'
ELASTICSEARCH_PASSWORD = 'yourpasswordhere'
ELASTICSEARCH_CA_CERT_PATH = None

# In order to avoid multiple workers on the same url
ELASTICSEARCH_RANDOM_BUCKETS = 20
MAX_ES_RETRIES = 10
ES_RETRY_DELAY = 1
URLS_INDEX = 'crawler'

# Selenium config
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

# This option only makes sense to be activated when you have an external
# script packing data to database, since all crawler data is already
# filtered while urls are entering.
REMOVE_INVALID_URLS = True

# How long will it  wait until consider the url is not responding
# This will deal with pages asking for basic authentication, and
# streaming urls that never ends.
MAX_DOWNLOAD_TIME = 120

# How many iterations should the python script runs. This does not
# apply to the wrapper, that makes it run continuously.
ITERATIONS = 10

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
    "Oni", "Tengu", "Kappa", "Kitsune", "Tanuki", "Yuki-onna", "Rokurokubi",
]

# be_greedy = True - Save urls to database that might not work,
# since have not matched any regex.
BE_GREEDY = False

# Do not crawl these domains.
HOST_REGEX_BLOCK_LIST = [
    r'localhost:4443$',
    r'(^|\.)google\.com$',
    r'(^|\.)gstatic\.com$',
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

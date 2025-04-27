#!/usr/bin/python3
SELENIUM_WIDTH=1920
SELENIUM_HEIGHT=1080
EMBED_PORT="4443"
USE_PROXY=False
PROXY_HOST='http://10.20.10.19:8123'
MAX_DOWNLOAD_TIME = 120
EXTRACT_WORDS=True
HUNT_OPEN_DIRECTORIES=True
DOWNLOAD_MIDIS=True
MIDIS_FOLDER='midis'
DOWNLOAD_AUDIOS=True
AUDIOS_FOLDER='audios'
DOWNLOAD_PDFS=True
PDFS_FOLDER='pdfs'
DOWNLOAD_VIDEOS=True
VIDEOS_FOLDER='videos'
INITIAL_URL='http://httpforever.com/'
ITERATIONS=10
NSFW_MIN_PROBABILITY=.78
CATEGORIZE_NSFW=True
SAVE_NSFW=True
NSFW_FOLDER='images/nsfw'
SAVE_SFW=False
SFW_FOLDER='images/sfw'
MIN_NSFW_RES = 64 * 64
SAVE_ALL_IMAGES=False
IMAGES_FOLDER='images'
DIRECT_LINK_DOWNLOAD_FOLDER='/dev/null'
HTTPS_EMBED='https://localhost:'+EMBED_PORT+'/embed.html?url='
GROUP_DOMAIN_LEVEL=2
ELASTICSEARCH_HOST="127.0.0.1"
ELASTICSEARCH_PORT=9200
ELASTICSEARCH_USER='elastic'
ELASTICSEARCH_PASSWORD='yourpassword'
ELASTICSEARCH_CA_CERT_PATH=None
ELASTICSEARCH_RANDOM_BUCKETS=7
MAX_ES_RETRIES=10
ES_RETRY_DELAY=1
WORDS_REMOVE_SPECIAL_CHARS=True
WORDS_TO_LOWER=True
WORDS_MIN_LEN=3
#WORDS_MAX_LEN * WORDS_MAX_WORDS should be under 1 million for a default elastic search env
WORDS_MAX_LEN=40
WORDS_MAX_WORDS=24999
URLS_INDEX='urls'
BLOCK_CSS=False
PERFORMANCE_OPTIMIZED=False
FORCE_IMAGE_LOAD=True
RANDOM_SITES_QUEUE=100
MAX_DIR_LEVELS=7
MAX_HOST_LEVELS=7
URL_FILE='urls.json'
EXTRACT_RAW_WEBCONTENT=True
EXTRACT_MIN_WEBCONTENT=True
MAX_WEBCONTENT_SIZE=999999 #should be under 1 million for a default elastic search env

#URL File format
#[
#{"url": "http://odd.com/subdir/", "host": "odd.com"},
#{"url": "http://nuu.com/a/b/c/", "host": "nuu.com"},
#]


#be_greedy = True - Save urls to database that might not work, since have not matched any regex.
BE_GREEDY=False

# host_regex_block_list do not crawl these domains. 
host_regex_block_list = [
    r'localhost:4443$',
    r'(^|\.)instagram\.com$',
]

#do not crawl urls that match any of these regexes
url_regex_block_list = [
    '/noticias/modules/noticias/modules/noticias/modules/',
    '/images/images/images/images/',
]

host_regex_allow_list = [r'.*']

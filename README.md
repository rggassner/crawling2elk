# Crawler with NSFW Detection, Elasticsearch Integration 

This is a modular, scalable web crawling framework built for advanced scraping, data enrichment, and media classification. It features built-in support for:

-    Open directory detection
    
-    Advanced URL pattern handling and filtering
    
-    NSFW content detection using `opennsfw2`
    
-    Elasticsearch integration for scalable storage and analysis
    
-    Selenium with stealth via `selenium-wire` and `fake-useragent`
    
-    Word extraction for keyword indexing
    
-    Email harvesting
    
-    URL de-duplication, allow/block listing, and intelligent path handling

-    **Smart link discovery** – supports relative/absolute URL normalization and classification.

-    **Email Scraper** – detects and stores emails.
    
-   **Pluggable Architecture** – easily extend with new URL handlers using decorators.
    
-   **Error-tolerant** – many defensive checks for robustness.
    
-   **Configurable via `config.py`** – fully customizable logic and thresholds.

-   **Real-Time SSL Certificate Generation** - Automatically generates a self-signed SSL certificate for secure local web interfaces.
    
-   **Domain Relation Extraction** - Extracts host relationships (e.g., parent-child domain links) for graph building and dependency analysis.


* * *

##  Requirements

You’ll need the following installed:

`apt install pyenv nmap chromium-chromedriver expect libavif-dev`

Install elasticdump via npm if you plan to backup/restore:

`apt install npm`

`npm install -g elasticdump`

Python 3.11.11 is recommended:

`pyenv install 3.11.11`

Create a virtual environment to run the script

```
~/.pyenv/versions/3.11.11/bin/python -m venv venv
source venv/bin/activate
pip install --upgrade pip
```

Install dependencies:

`pip install -r requirements.txt`


* * *

Suggestion for additional privacy, add the following lines to the hosts of your crawler clients:

/etc/hosts

```
127.0.0.1 plausible.io
127.0.0.1 www.plausible.io
```

## Configuration

All tunables live in `config.py`:

-   Allow/block regex patterns
    
-   Word processing settings (`WORDS_TO_LOWER`, etc.)
    
-   Elasticsearch connection info
    
-   Custom URL handler regex
    

* * *

## Function Highlights

-   `db_insert_if_new_url()` – inserts URL if new or updates with `visited`, NSFW status, resolution, etc.
    
-   `db_update_url()` – updates metadata of visited URLs.
    
-   `get_words()` – extracts clean keywords from soup or text.
    
-   `get_links()` – extracts links and dispatches to appropriate handlers.
    
-   `get_directory_tree()` – builds a tree of parent paths from a URL.
    
-   `get_url_function()` – decorator that registers functions to handle URL regexes.
    

* * *

## Extending the Engine

Add your own URL handler like this:


`@function_for_url([r"your-regex-here"]) def custom_handler(args):     # your logic     return True`

This makes the engine modular and powerful for specialized scraping and analysis tasks.

* * *

## Notes

-   URLs are hashed with SHA-256 to use as Elasticsearch document IDs.
    
-   Avoid scanning with identifiable fingerprints: user agents are randomized.
    
-   Warnings are suppressed to reduce noise, but can be enabled for debugging.
    
* * *

## Related Stuff

- https://wiki.archiveteam.org/index.php?title=ArchiveBot

- http://archivebot.com/

* * *

## TODO

- Create crawling method to websearch a random word.

* * *

##  Author Notes

Built for performance, flexibility, and stealth. Use responsibly.


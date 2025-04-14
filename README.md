# 🕷️ Smart Crawler with NSFW Detection, Elasticsearch Integration & Link Intelligence

This is a modular, scalable web crawling framework built for advanced scraping, data enrichment, and media classification. It features built-in support for:

-   ✅ Open directory detection
    
-   🔍 Advanced URL pattern handling and filtering
    
-   🧠 NSFW content detection using `opennsfw2`
    
-   🧱 Elasticsearch integration for scalable storage and analysis
    
-   🦾 Selenium with stealth via `selenium-wire` and `fake-useragent`
    
-   🧠 Word extraction for keyword indexing
    
-   🔗 Email harvesting
    
-   📂 URL de-duplication, allow/block listing, and intelligent path handling
    

* * *

## 🚀 Features

-   **Smart link discovery** – supports relative/absolute URL normalization and classification.
    
-   **Open Directory Detection** – detects classic index pages.
    
-   **NSFW Classifier** – classifies images using `opennsfw2` model.
    
-   **Email Scraper** – detects and stores emails.
    
-   **Elasticsearch-backed** – stores and updates URL metadata, deduplicated using a SHA-256 hash.
    
-   **Pluggable Architecture** – easily extend with new URL handlers using decorators.
    
-   **Error-tolerant** – many defensive checks for robustness.
    
-   **Configurable via `config.py`** – fully customizable logic and thresholds.
    

* * *

## 🧱 Requirements

You’ll need the following installed:

-   `sudo apt install python3-pip`
  
-   `sudo apt install expect`
  
-   `sudo apt install chromium-chromedriver`

Install dependencies:

`pip install -r requirements.txt`

Main external libraries used:

-   `selenium-wire`
    
-   `opennsfw2`
    
-   `fake-useragent`
    
-   `beautifulsoup4`
    
-   `Pillow`
    
-   `elasticsearch`
    
-   `numpy`
    

* * *

## 🛠️ Configuration

All tunables live in `config.py`:

-   Allow/block regex patterns
    
-   Word processing settings (`WORDS_TO_LOWER`, etc.)
    
-   Elasticsearch connection info
    
-   Custom URL handler regex
    

* * *

## 📚 Function Highlights

-   `db_insert_if_new_url()` – inserts URL if new or updates with `visited`, NSFW status, resolution, etc.
    
-   `db_update_url()` – updates metadata of visited URLs.
    
-   `get_words()` – extracts clean keywords from soup or text.
    
-   `get_links()` – extracts links and dispatches to appropriate handlers.
    
-   `get_directory_tree()` – builds a tree of parent paths from a URL.
    
-   `get_url_function()` – decorator that registers functions to handle URL regexes.
    

* * *

## 🧩 Extending the Engine

Add your own URL handler like this:


`@function_for_url([r"your-regex-here"]) def custom_handler(args):     # your logic     return True`

This makes the engine modular and powerful for specialized scraping and analysis tasks.

* * *

## 🔒 Notes

-   URLs are hashed with SHA-256 to use as Elasticsearch document IDs.
    
-   Avoid scanning with identifiable fingerprints: user agents are randomized.
    
-   Warnings are suppressed to reduce noise, but can be enabled for debugging.
    
* * *

## 💬 Author Notes

Built for performance, flexibility, and stealth. Use responsibly.

